import json
from openai import OpenAI
import inspect

# 전역 콜백 변수 (간단한 시각화 연동을 위해 사용)
_GLOBAL_CALLBACK = None

def set_global_callback(callback):
    """
    모든 Swarm 인스턴스에서 공유할 콜백을 설정합니다.
    Streamlit UI 등에서 하위 에이전트의 동작까지 추적하기 위함입니다.
    """
    global _GLOBAL_CALLBACK
    _GLOBAL_CALLBACK = callback

class Agent:
    def __init__(self, name="Agent", model="gpt-4o", instructions="You are a helpful agent.", tools=None):
        self.name = name
        self.model = model
        self.instructions = instructions
        self.tools = tools if tools else []

class Swarm:
    def __init__(self, client=None):
        self.client = client if client else OpenAI()

    def run(self, agent, messages, context_variables=None, stream=False, debug=False, callback=None):
        input_callback = callback
        
        # 콜백 래퍼 함수 (지역 콜백 + 전역 콜백 모두 실행)
        def trigger_callback(event, data):
            if input_callback:
                input_callback(event, data)
            if _GLOBAL_CALLBACK:
                _GLOBAL_CALLBACK(event, data)

        if context_variables is None:
            context_variables = {}
            
        current_messages = messages.copy()
        
        # 시스템 프롬프트 설정 (중복 방지 로직 추가 가능)
        system_message = {"role": "system", "content": agent.instructions}
        # 이미 시스템 메시지가 맨 앞에 있다면 덮어쓰거나 생략해야 하지만, 단순화를 위해 추가
        current_messages.insert(0, system_message)

        if callback or _GLOBAL_CALLBACK:
            trigger_callback("agent_start", agent.name)

        while True:
            # 도구 정의 변환
            tools_schema = [self.function_to_schema(tool) for tool in agent.tools]
            
            # API 호출
            response = self.client.chat.completions.create(
                model=agent.model,
                messages=current_messages,
                tools=tools_schema if tools_schema else None,
            )
            
            message = response.choices[0].message
            current_messages.append(message)

            # 도구 호출이 없으면 종료 및 반환
            if not message.tool_calls:
                return message

            # 도구 실행
            for tool_call in message.tool_calls:
                function_name = tool_call.function.name
                arguments = json.loads(tool_call.function.arguments)
                
                # 해당 이름의 함수 찾기
                tool_func = next((t for t in agent.tools if t.__name__ == function_name), None)
                
                if tool_func:
                    # 도구 시작 알림
                    trigger_callback("tool_start", {"name": function_name, "arguments": arguments})

                    # 도구 실행 결과
                    try:
                        result = tool_func(**arguments)
                        # 결과를 문자열로 변환 (JSON)
                        result_str = str(result)
                    except Exception as e:
                        result_str = f"Error: {e}"
                        
                    # 도구 완료 알림
                    trigger_callback("tool_end", {"name": function_name, "result": result_str})
                        
                    # 도구 실행 결과 메시지 추가
                    current_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": function_name,
                        "content": result_str
                    })
                    
                    # 도구 실행 이벤트를 스트림 등으로 외부 알림 가능
                    if debug:
                        print(f"[Tool Executed] {function_name} -> {result_str}")

    def function_to_schema(self, func):
        """
        간단한 함수 -> OpenAI Tool 스키마 변환기
        Docstring 파싱 등 더 복잡한 로직이 필요할 수 있음
        """
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
            type(None): "null"
        }

        try:
            signature = inspect.signature(func)
        except ValueError:
            return None

        parameters = {}
        required = []
        
        for param in signature.parameters.values():
            param_type = type_map.get(param.annotation, "string")
            parameters[param.name] = {"type": param_type}
            if param.default == inspect.Parameter.empty:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": func.__name__,
                "description": (func.__doc__ or "").strip(),
                "parameters": {
                    "type": "object",
                    "properties": parameters,
                    "required": required,
                },
            },
        }
