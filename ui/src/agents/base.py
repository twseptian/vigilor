from src.core.llm import ClaudeEngine
from src.core.workspace import WorkspaceManager

class BaseAgent:
    def __init__(self, engine: ClaudeEngine):
        self.engine = engine
        self.system_prompt = "You are a specialized AI pentesting agent."
        
    async def execute(self, workspace: WorkspaceManager):
        raise NotImplementedError("Each agent must implement the execute method")
        
    def _format_tools(self) -> list:
        # Define base tools Anthropic format
        return []
