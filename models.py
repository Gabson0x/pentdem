import os
import asyncio
from dotenv import load_dotenv
load_dotenv()

from openai import AsyncOpenAI
import anthropic
from typing import Dict, Any, Optional


class ModelClient:
    """High-throughput multi-model client with concurrency control and smart fallback routing."""

    MAX_CONCURRENT = 3
    RATE_LIMIT_DELAY = 0.5

    def __init__(self):
        self.openai_clients: Dict[str, AsyncOpenAI] = {}
        self.anthropic_client: Optional[anthropic.AsyncAnthropic] = None
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        self._init_clients()
        self._provider_health = {k: True for k in self.openai_clients}
        if self.anthropic_client:
            self._provider_health["minimax"] = True

    def _init_clients(self):
        if key := os.getenv("DEEPSEEK_API_KEY"):
            if not key.startswith("your_") and not key.startswith("sk-"):
                pass
            self.openai_clients["deepseek"] = AsyncOpenAI(
                api_key=key,
                base_url="https://api.deepseek.com/v1"
            )
        if key := os.getenv("KIMI_API_KEY"):
            self.openai_clients["kimi"] = AsyncOpenAI(
                api_key=key,
                base_url="https://api.moonshot.ai/v1"
            )
        if key := os.getenv("QWEN_API_KEY"):
            if not key.startswith("your_"):
                self.openai_clients["qwen"] = AsyncOpenAI(
                    api_key=key,
                    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
                )
        if key := os.getenv("GLM_API_KEY"):
            if not key.startswith("your_"):
                self.openai_clients["glm"] = AsyncOpenAI(
                    api_key=key,
                    base_url="https://open.bigmodel.cn/api/paas/v4"
                )
        if key := os.getenv("FEATHERLESS_API_KEY"):
            self.openai_clients["featherless"] = AsyncOpenAI(
                api_key=key,
                base_url="https://api.featherless.ai/v1"
            )
        # MiniMax via OpenAI-compatible API
        if key := os.getenv("MINIMAX_API_KEY"):
            if not key.startswith("your_"):
                self.openai_clients["minimax"] = AsyncOpenAI(
                    api_key=key,
                    base_url="https://api.minimaxi.com/v1"
                )
        # Also support Anthropic SDK for MiniMax (legacy)
        if os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_BASE_URL"):
            self.anthropic_client = anthropic.AsyncAnthropic(
                api_key=os.getenv("ANTHROPIC_API_KEY"),
                base_url=os.getenv("ANTHROPIC_BASE_URL")
            )

    async def generate(self, prompt: str, model: str = "featherless",
                       system_prompt: str = None, temperature: float = 0.1) -> str:
        # MiniMax: try OpenAI-compatible first, fallback to Anthropic SDK
        if model == "minimax":
            if "minimax" in self.openai_clients:
                return await self._generate_openai(prompt, model, system_prompt, temperature)
            elif self.anthropic_client:
                return await self._generate_anthropic(prompt, system_prompt, temperature)

        async with self._semaphore:
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
            try:
                return await asyncio.wait_for(
                    self._generate_openai(prompt, model, system_prompt, temperature),
                    timeout=30
                )
            except asyncio.TimeoutError:
                # Fallback to featherless on timeout
                if model != "featherless":
                    return await self._generate_openai(prompt, "featherless", system_prompt, temperature)
                return "Analysis timeout"

    async def _generate_openai(self, prompt: str, model: str,
                                system_prompt: str = None, temperature: float = 0.1) -> str:
        provider = self._resolve_provider(model)
        client = self.openai_clients.get(provider)
        actual_model = self._get_model_name(provider, model)

        if not client:
            raise ValueError(f"No client available for model={model}, provider={provider}")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = await asyncio.wait_for(
                    client.chat.completions.create(
                        model=actual_model,
                        messages=messages,
                        temperature=temperature,
                        max_tokens=4096,
                    ),
                    timeout=20,
                )
                return response.choices[0].message.content
            except Exception as e:
                error_msg = str(e).lower()
                # Rate limit (429) → retry with backoff
                if "429" in error_msg or "rate" in error_msg or "too many" in error_msg:
                    if attempt < max_retries - 1:
                        wait_time = (2 ** attempt) * 2  # 2s, 4s, 8s
                        print(f"    Rate limited on {provider}, retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                # Other errors → fallback
                fallback = self._get_fallback(provider)
                if fallback and fallback in self.openai_clients:
                    try:
                        fb_client = self.openai_clients[fallback]
                        fb_response = await asyncio.wait_for(
                            fb_client.chat.completions.create(
                                model=self._get_model_name(fallback, fallback),
                                messages=messages,
                                temperature=temperature,
                                max_tokens=4096,
                            ),
                            timeout=20,
                        )
                        return fb_response.choices[0].message.content
                    except Exception:
                        pass
                return "Analysis unavailable - returning default"

        return "Analysis unavailable - max retries exceeded"

    async def _generate_anthropic(self, prompt: str, system_prompt: str = None,
                                   temperature: float = 0.1) -> str:
        kwargs = {
            "model": "MiniMax-M3",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        try:
            message = await asyncio.wait_for(
                self.anthropic_client.messages.create(**kwargs),
                timeout=30,
            )
            for block in message.content:
                if block.type == "text":
                    return block.text
        except Exception:
            pass
        return "Analysis unavailable"

    def _resolve_provider(self, model: str) -> str:
        provider_map = {
            "deepseek": "deepseek",
            "deepseek-v3": "deepseek",
            "deepseek-r1": "deepseek",
            "kimi": "kimi",
            "kimi-k2.6": "kimi",
            "qwen": "qwen",
            "qwen-plus": "qwen",
            "glm": "glm",
            "glm-4": "glm",
            "glm-4-flash": "glm",
            "featherless": "featherless",
            "minimax": "minimax",
        }
        return provider_map.get(model, "featherless")

    def _get_model_name(self, provider: str, requested: str) -> str:
        model_names = {
            "deepseek": "deepseek-chat",
            "kimi": "moonshot-v1-128k",
            "qwen": "qwen-plus",
            "glm": "glm-4-flash",
            "minimax": "MiniMax-M3",
            "featherless": {
                "reasoning": "deepseek-ai/DeepSeek-V4-Flash",
                "code": "moonshotai/Kimi-K2.7-Code",
                "analysis": "zai-org/GLM-5.2",
                "report": "Qwen/Qwen3.6-35B-A3B",
                "default": "zai-org/GLM-5.2",
            }
        }
        if provider == "featherless":
            mapping = model_names["featherless"]
            if requested in ("deepseek-r1", "reasoning"):
                return mapping["reasoning"]
            elif requested in ("code", "exploit"):
                return mapping["code"]
            elif requested in ("analysis", "validate"):
                return mapping["analysis"]
            elif requested in ("report", "write"):
                return mapping["report"]
            return mapping["default"]
        return model_names.get(provider, "deepseek-chat")

    def _get_fallback(self, failed_provider: str) -> Optional[str]:
        fallback_order = ["featherless", "deepseek", "glm", "kimi", "qwen"]
        for fb in fallback_order:
            if fb != failed_provider and fb in self.openai_clients:
                return fb
        return None

    def get_task_model(self, task_type: str) -> str:
        """
        Smart model routing: cheap models for high-volume, expensive for reasoning.

        Tier 1 (GLM-4-Flash / Kimi): Wordlist gen, triage, fuzzing analysis, basic validation
        Tier 2 (featherless/free): Chain reasoning, exploitability judgment, report writing
        """
        assignments = {
            # Recon — cheap (high volume, low reasoning)
            "subdomain_enum": "glm",
            "url_crawling": "glm",
            "js_analysis": "glm",
            "directory_fuzzing": "glm",
            "tech_fingerprint": "minimax",
            # Hunting — cheap for standard tests, expensive for analysis
            "vulnerability_analysis": "glm",
            "exploit_writing": "featherless",
            "idor_testing": "featherless",
            "ssrf_testing": "glm",
            "xss_testing": "glm",
            "sqli_testing": "minimax",
            "rce_testing": "featherless",
            "ssti_testing": "glm",
            "lfi_testing": "glm",
            "path_traversal_testing": "featherless",
            "nosql_testing": "glm",
            "graphql_testing": "glm",
            "jwt_testing": "glm",
            "auth_bypass_testing": "featherless",
            "open_redirect_testing": "glm",
            "deserialization_testing": "glm",
            "race_condition_testing": "glm",
            "bizlogic_testing": "glm",
            "api_security_testing": "glm",
            # Validation — cheap for filtering, expensive for judgment
            "triage": "glm",
            "severity": "glm",
            "dedup": "featherless",
            "cvss_scoring": "minimax",
            "poc_generation": "glm",
            # Chains & Reporting — expensive (high reasoning, low volume)
            "chain_analysis": "featherless",
            "report_writing": "featherless",
            "pattern_learning": "featherless",
            "knowledge_update": "featherless",
            # Source code analysis
            "source_code_audit": "featherless",
            "dependency_analysis": "featherless",
            "pr_review": "featherless",
        }
        return assignments.get(task_type, "featherless")

    def get_available_models(self) -> list:
        available = []
        if self.anthropic_client:
            available.append({"provider": "minimax", "model": "MiniMax-M3", "name": "MiniMax-M3"})
        for provider in ["deepseek", "kimi", "qwen", "glm"]:
            if provider in self.openai_clients:
                available.append({"provider": provider, "model": f"{provider}-chat", "name": provider.title()})
        if "featherless" in self.openai_clients:
            for name, model_id in [
                ("GLM-5.2 (Analysis)", "zai-org/GLM-5.2"),
                ("DeepSeek-V4 (Reasoning)", "deepseek-ai/DeepSeek-V4-Flash"),
                ("Qwen3.6 (Report)", "Qwen/Qwen3.6-35B-A3B"),
                ("Kimi-K2.7 (Code)", "moonshotai/Kimi-K2.7-Code"),
            ]:
                available.append({"provider": "featherless", "model": model_id, "name": name})
        return available


MODEL_ASSIGNMENTS = {
    "ReconSkill": "glm",        # Cheap — high volume recon analysis
    "HuntSkill": "glm",         # Cheap — standard payload injection
    "ChainSkill": "featherless", # Expensive — complex chain reasoning
    "KnowledgeSkill": "glm",    # Cheap — pattern matching
    "ValidateSkill": "glm",     # Cheap — filtering/validation
    "ReportSkill": "featherless", # Expensive — structured report writing
    "MemorySkill": "glm",       # Cheap — storage/retrieval
}

model_client = ModelClient()
