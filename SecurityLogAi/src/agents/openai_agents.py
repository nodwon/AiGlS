
import json
from openai import OpenAI
import inspect

class Agent:
    def __init__(self, name="Agent", model="gpt-4o", instructions="You are a helpful agent.", tools=None):
        self.name = name
        self.model = model
        self.instructions = instructions
        self.tools = tools if tools else []

class Swarm:
    def __init__(self, client=None):
        self.client = client if client else OpenAI()

    def run(self, agent, messages, context_variables=None, stream=False, debug=False):
        if context_variables is None:
            context_variables = {}
            
        current_messages = messages.copy()
        
        # 시스템 프롬프트 설정
        system_message = {"role": "system", "content": agent.instructions}
        current_messages.insert(0, system_message)

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
                    # 도구 실행 결과
                    try:
                        result = tool_func(**arguments)
                        # 결과를 문자열로 변환 (JSON 등)
                        result_str = str(result)
                    except Exception as e:
                        result_str = f"Error: {e}"
                        
                    # 도구 실행 결과 메시지 추가
                    current_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": function_name,
                        "content": result_str
                    })
                    
                    # (선택 사항) 도구 실행 이벤트를 스트림 등으로 외부 알림 가능
                    if debug:
                        print(f"[Tool Executed] {function_name} -> {result_str}")

    def function_to_schema(self, func):
        """
        간단한 함수 -> OpenAI Tool 스키마 변환기
        (실제로는 Docstring 파싱 등 더 복잡한 로직이 필요할 수 있음)
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
