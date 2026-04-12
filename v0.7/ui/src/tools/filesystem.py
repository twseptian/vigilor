import os

class FilesystemTool:
    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        
    def _is_safe_path(self, path: str) -> bool:
        """Prevent directory traversal attacks."""
        target_path = os.path.abspath(os.path.join(self.root_dir, path))
        return target_path.startswith(self.root_dir)
        
    def read_file(self, filepath: str) -> str:
        if not self._is_safe_path(filepath):
            return "Error: Path traversal attempt blocked."
        try:
            with open(os.path.join(self.root_dir, filepath), 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {e}"
            
    def list_dir(self, directory: str = ".") -> list:
        if not self._is_safe_path(directory):
            return ["Error: Path traversal attempt blocked."]
        try:
            return os.listdir(os.path.join(self.root_dir, directory))
        except Exception as e:
            return [f"Error listing directory: {e}"]
