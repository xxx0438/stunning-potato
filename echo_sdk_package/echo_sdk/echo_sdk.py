import requests
from typing import Any, Dict, List, Optional


class EchoPromptClient:
    """
    Echo Agent Governance 官方 Python SDK。
    用于在业务代码中获取受治理的 Agent 上下文、执行运行时策略检查并记录审计日志。
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        """
        初始化客户端。
        :param base_url: 后端 API 的基础地址
        """
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        """内部请求包装器，处理错误和数据解析。"""
        url = f"{self.base_url}{endpoint}"
        response = requests.request(method, url, **kwargs)
        
        if not response.ok:
            error_msg = response.text
            try:
                error_msg = response.json().get("detail", response.text)
            except ValueError:
                pass
            raise Exception(f"API Error {response.status_code}: {error_msg}")
            
        return response.json()

    # ==========================================
    # 资产管理 (Context Assets)
    # ==========================================
    def create_asset(self, name: str, asset_type: str, owner: str, description: str = "", tags: List[str] = None) -> Dict:
        """创建一个新的 Agent context/prompt/workflow/skill 资产。"""
        payload = {
            "name": name,
            "asset_type": asset_type,
            "owner": owner,
            "description": description,
            "tags": tags or []
        }
        return self._request("POST", "/api/assets/", json=payload)

    # ==========================================
    # 业务调用 API (获取运行时的受治理配置)
    # ==========================================
    def get_active_prompt(self, asset_name: str) -> Dict:
        """
        [兼容旧方法] 获取指定资产当前处于 active 状态的配置（系统提示词、上下文、workflow、guardrails）。
        业务代码应该在每次调用大模型前调用此方法。
        """
        return self._request("GET", f"/api/services/assets/{asset_name}/active")

    def get_active_asset(self, asset_name: str) -> Dict:
        """获取指定 Agent 资产当前 active 版本的完整治理配置。"""
        return self.get_active_prompt(asset_name)

    def check_runtime_guardrails(
        self,
        tool_name: str,
        asset_version_id: Optional[int] = None,
        asset_name: Optional[str] = None,
        tool_args: Dict = None,
        input_variables: Dict = None,
        actor: str = "",
    ) -> Dict:
        """
        在 Agent 执行工具调用前执行运行时策略检查。
        返回 status=allow/review/block，以及触发的 guardrail findings。
        """
        payload = {
            "asset_version_id": asset_version_id,
            "asset_name": asset_name,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            "input_variables": input_variables or {},
            "actor": actor,
        }
        return self._request("POST", "/api/runtime/guardrails/check", json=payload)

    # ==========================================
    # 留痕与复盘 (Logs)
    # ==========================================
    def log_execution(self, asset_version_id: int, model_name: str, llm_output: str, 
                      input_variables: Dict = None, latency_ms: int = 0, 
                      token_usage: int = 0, request_id: Optional[str] = None) -> Dict:
        """将大模型的输入输出和性能指标异步/同步记录回 CMS 系统。"""
        payload = {
            "asset_version_id": asset_version_id,
            "request_id": request_id,
            "model_name": model_name,
            "input_variables": input_variables or {},
            "llm_output": llm_output,
            "latency_ms": latency_ms,
            "token_usage": token_usage
        }
        return self._request("POST", "/api/logs/", json=payload)

    # ==========================================
    # CI Gate 拦截检查 (CI/CD 集成)
    # ==========================================
    def check_ci_gate(self, commit_sha: str, is_ai_related: bool = True) -> Dict:
        """用于在 GitHub Actions 或 GitLab CI 中检查代码提交是否通过合规。"""
        payload = {
            "commit_sha": commit_sha,
            "is_ai_related": is_ai_related
        }
        return self._request("POST", "/api/ci/gate/check", json=payload)

    # ==========================================
    # 审计报告 / 演示数据
    # ==========================================
    def get_audit_summary(self) -> Dict:
        """获取资产、版本、变更、运行日志和 guardrail 覆盖率的审计摘要。"""
        return self._request("GET", "/api/audit/reports/summary")

    def seed_demo_data(self) -> Dict:
        """写入一组可直接演示的金融 Agent 治理样例数据。"""
        return self._request("POST", "/api/demo/seed")

