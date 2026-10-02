"""Loop local web app: SQLite-backed accounts, sessions, and practice progress."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from email.message import EmailMessage
import hashlib, hmac, json, os, re, secrets, sqlite3, time, smtplib, ssl, subprocess, tempfile, shutil

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "loop.sqlite3"
PBKDF2_ROUNDS = 310_000
SESSION_SECONDS = 30 * 24 * 60 * 60
EMAIL_TOKEN_SECONDS = 24 * 60 * 60
RESET_TOKEN_SECONDS = 60 * 60
PROBLEM_CATALOG = {"Two Sum", "Valid Parentheses", "Binary Search", "Longest Substring Without Repeating", "Container With Most Water", "Merge K Sorted Lists"}

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            language TEXT NOT NULL DEFAULT 'JavaScript',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS solved_problems (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            problem TEXT NOT NULL,
            solved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, problem)
        );
        CREATE TABLE IF NOT EXISTS algorithm_completions (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            algorithm TEXT NOT NULL,
            level TEXT NOT NULL,
            completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, algorithm)
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            track TEXT NOT NULL,
            title TEXT NOT NULL,
            issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, track, title)
        );
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "email_verified" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")

def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS).hex()

def mail_configured():
    return all(os.environ.get(key) for key in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"))

def send_email(recipient, subject, body):
    if not mail_configured():
        return False
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    message = EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context()) as smtp:
                smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                smtp.send_message(message)
        return True
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        print(f"Email delivery failed ({type(exc).__name__}).")
        return False

def create_email_token(table, user_id, ttl):
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with connect() as db:
        db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
        db.execute(f"INSERT INTO {table}(token_hash,user_id,expires_at) VALUES(?,?,?)", (digest, user_id, int(time.time()) + ttl))
    return raw

def send_verification(user_id, email):
    token = create_email_token("email_verification_tokens", user_id, EMAIL_TOKEN_SECONDS)
    base = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    return send_email(email, "Verify your Stepwise account", f"Welcome to Stepwise. Verify your email using this link (valid for 24 hours):\n\n{base}/?verify={token}\n")

def send_reset(user_id, email):
    token = create_email_token("password_reset_tokens", user_id, RESET_TOKEN_SECONDS)
    base = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    return send_email(email, "Reset your Stepwise password", f"Use this link to choose a new password (valid for one hour):\n\n{base}/?reset={token}\nIf you did not request this, ignore this message.\n")

PROBLEM_TESTS = {
    "Two Sum": [("twoSum([2,7,11,15],9)", [0,1]), ("twoSum([3,2,4],6)", [1,2]), ("twoSum([3,3],6)", [0,1])],
    "Valid Parentheses": [("isValid('()[]{}')", True), ("isValid('([{}])')", True), ("isValid('(]')", False)],
    "Binary Search": [("search([1,3,5,7,9],7)", 3), ("search([-4,0,8,12],-4)", 0), ("search([2,5,8],7)", -1)],
    "Longest Substring Without Repeating": [("lengthOfLongestSubstring('abcabcbb')", 3), ("lengthOfLongestSubstring('bbbbb')", 1), ("lengthOfLongestSubstring('')", 0)],
    "Container With Most Water": [("maxArea([1,8,6,2,5,4,8,3,7])", 49), ("maxArea([1,1])", 1), ("maxArea([4,3,2,1,4])", 16)],
    "Merge K Sorted Lists": [("mergeKLists([[1,4,5],[1,3,4],[2,6]])", [1,1,2,3,4,4,5,6]), ("mergeKLists([])", [])],
}

def _python_runner(problem, source):
    expressions = PROBLEM_TESTS[problem]
    calls = "[" + ",".join("(" + expr + "," + repr(expected) + ")" for expr, expected in expressions) + "]"
    return source + "\n_stepwise_results=" + calls + "\nfor _i,(_actual,_expected) in enumerate(_stepwise_results,1):\n    if _actual != _expected: print('STEPWISE_FAIL:'+str(_i)+': expected '+repr(_expected)+' got '+repr(_actual)); raise SystemExit(1)\n    print('STEPWISE_PASS:'+str(_i))\n"

def _java_runner(problem, source):
    fixtures = {
        "Two Sum": "int[][] a={{2,7,11,15},{3,2,4},{3,3}}; int[] t={9,6,6}; int[][] e={{0,1},{1,2},{0,1}}; for(int i=0;i<a.length;i++) if(!Arrays.equals(s.twoSum(a[i],t[i]),e[i])) throw new RuntimeException(\"case \"+i);",
        "Valid Parentheses": "String[] a={\"()[]{}\",\"([{}])\",\"(]\"}; boolean[] e={true,true,false}; for(int i=0;i<a.length;i++) if(s.isValid(a[i])!=e[i]) throw new RuntimeException(\"case \"+i);",
        "Binary Search": "int[][] a={{1,3,5,7,9},{-4,0,8,12},{2,5,8}}; int[] t={7,-4,7}, e={3,0,-1}; for(int i=0;i<a.length;i++) if(s.search(a[i],t[i])!=e[i]) throw new RuntimeException(\"case \"+i);",
        "Longest Substring Without Repeating": "String[] a={\"abcabcbb\",\"bbbbb\",\"\"}; int[] e={3,1,0}; for(int i=0;i<a.length;i++) if(s.lengthOfLongestSubstring(a[i])!=e[i]) throw new RuntimeException(\"case \"+i);",
        "Container With Most Water": "int[][] a={{1,8,6,2,5,4,8,3,7},{1,1},{4,3,2,1,4}}; int[] e={49,1,16}; for(int i=0;i<a.length;i++) if(s.maxArea(a[i])!=e[i]) throw new RuntimeException(\"case \"+i);",
        "Merge K Sorted Lists": "int[][][] a={{{1,4,5},{1,3,4},{2,6}}, {}}; int[][] e={{1,1,2,3,4,4,5,6},{}}; for(int i=0;i<a.length;i++) if(!Arrays.equals(s.mergeKLists(a[i]),e[i])) throw new RuntimeException(\"case \"+i);",
    }
    return "import java.util.*;\n" + source + "\npublic class Main { public static void main(String[] z) { Solution s=new Solution(); " + fixtures[problem] + " System.out.println(\"PASS\"); } }\n"

ALGORITHM_CASES = {
    "Linear Search": {"python": "linearSearch([8,3,11,6,2],6) == 3 and linearSearch([5,4],9) == -1", "java": "if(s.linearSearch(new int[]{8,3,11,6,2},6)!=3 || s.linearSearch(new int[]{5,4},9)!=-1) throw new RuntimeException(\"case\");"},
    "Binary Search": {"python": "binarySearch([3,7,11,14,18,23,29],23) == 5 and binarySearch([1,4,9],2) == -1", "java": "if(s.binarySearch(new int[]{3,7,11,14,18,23,29},23)!=5 || s.binarySearch(new int[]{1,4,9},2)!=-1) throw new RuntimeException(\"case\");"},
    "Bubble Sort": {"python": "bubbleSort([4,1,3,2]) == [1,2,3,4] and bubbleSort([]) == []", "java": "if(!Arrays.equals(s.bubbleSort(new int[]{4,1,3,2}),new int[]{1,2,3,4}) || !Arrays.equals(s.bubbleSort(new int[]{}),new int[]{})) throw new RuntimeException(\"case\");"},
    "Selection Sort": {"python": "selectionSort([7,2,9,1]) == [1,2,7,9]", "java": "if(!Arrays.equals(s.selectionSort(new int[]{7,2,9,1}),new int[]{1,2,7,9})) throw new RuntimeException(\"case\");"},
    "Insertion Sort": {"python": "insertionSort([5,2,4,1]) == [1,2,4,5]", "java": "if(!Arrays.equals(s.insertionSort(new int[]{5,2,4,1}),new int[]{1,2,4,5})) throw new RuntimeException(\"case\");"},
    "Two Pointers": {"python": "twoSumSorted([1,2,4,6,8,9,11,14],13) == [1,6]", "java": "if(!Arrays.equals(s.twoSumSorted(new int[]{1,2,4,6,8,9,11,14},13),new int[]{1,6})) throw new RuntimeException(\"case\");"},
    "Stack": {"python": "isValid('([]{})') is True and isValid('([)]') is False", "java": "if(!s.isValid(\"([]{})\") || s.isValid(\"([)]\")) throw new RuntimeException(\"case\");"},
    "Hash Map Lookup": {"python": "twoSum([4,9,2,7],13) == [0,1]", "java": "if(!Arrays.equals(s.twoSum(new int[]{4,9,2,7},13),new int[]{0,1})) throw new RuntimeException(\"case\");"},
    "Merge Sort": {"python": "mergeSort([8,3,6,2]) == [2,3,6,8]", "java": "if(!Arrays.equals(s.mergeSort(new int[]{8,3,6,2}),new int[]{2,3,6,8})) throw new RuntimeException(\"case\");"},
    "Quick Sort": {"python": "quickSort([9,3,7,1,5]) == [1,3,5,7,9]", "java": "if(!Arrays.equals(s.quickSort(new int[]{9,3,7,1,5}),new int[]{1,3,5,7,9})) throw new RuntimeException(\"case\");"},
    "Sliding Window": {"python": "maxWindow([2,1,5,1,3,2],3) == 9", "java": "if(s.maxWindow(new int[]{2,1,5,1,3,2},3)!=9) throw new RuntimeException(\"case\");"},
    "Backtracking": {"python": "len(subsets([1,2,3])) == 8", "java": "if(s.subsets(new int[]{1,2,3}).size()!=8) throw new RuntimeException(\"case\");"},
    "Longest Common Subsequence": {"python": "lcs('abcde','ace') == 3", "java": "if(s.lcs(\"abcde\",\"ace\")!=3) throw new RuntimeException(\"case\");"},
    "Dynamic Programming · Knapsack": {"python": "knapsack([[1,1],[3,4],[4,5],[5,7]],7) == 9", "java": "if(s.knapsack(new int[][]{{1,1},{3,4},{4,5},{5,7}},7)!=9) throw new RuntimeException(\"case\");"},
    "Queue": {"python": "queueOrder() == [4,7]", "java": "if(!Arrays.equals(s.queueOrder(),new int[]{4,7})) throw new RuntimeException(\"case\");"},
    "Linked List Reversal": {"python": "reverseList([1,2,3]) == [3,2,1]", "java": "if(!Arrays.equals(s.reverseList(new int[]{1,2,3}),new int[]{3,2,1})) throw new RuntimeException(\"case\");"},
    "Tree DFS": {"python": "preorder([1,2,3,4,5,6,7]) == [1,2,4,5,3,6,7]", "java": "if(!Arrays.equals(s.preorder(new int[]{1,2,3,4,5,6,7}),new int[]{1,2,4,5,3,6,7})) throw new RuntimeException(\"case\");"},
    "Tree BFS": {"python": "levelOrder([1,2,3,4,5,6,7]) == [1,2,3,4,5,6,7]", "java": "if(!Arrays.equals(s.levelOrder(new int[]{1,2,3,4,5,6,7}),new int[]{1,2,3,4,5,6,7})) throw new RuntimeException(\"case\");"},
    "BST Search": {"python": "searchBST([3,5,8],3) == 3", "java": "if(s.searchBST(new int[]{3,5,8},3)!=3) throw new RuntimeException(\"case\");"},
    "Heap / Priority Queue": {"python": "heapPeek([5,2,4]) == 2", "java": "if(s.heapPeek(new int[]{5,2,4})!=2) throw new RuntimeException(\"case\");"},
    "Topological Sort": {"python": "(lambda r: len(r)==4 and r.index(0)<r.index(1) and r.index(0)<r.index(2) and r.index(1)<r.index(3) and r.index(2)<r.index(3))(topo(4,[[0,1],[0,2],[1,3],[2,3]]))", "java": "if(!s.validTopo(s.topo(4,new int[][]{{0,1},{0,2},{1,3},{2,3}}),4,new int[][]{{0,1},{0,2},{1,3},{2,3}})) throw new RuntimeException(\"case\");"},
    "Union Find": {"python": "unionCheck() is True", "java": "if(!s.unionCheck()) throw new RuntimeException(\"case\");"},
    "Dijkstra": {"python": "dijkstra([[[1,1],[2,4]],[[2,2]],[]],0) == [0,1,3]", "java": "if(!Arrays.equals(s.dijkstra(new int[][][]{{{1,1},{2,4}},{{2,2}},{}},0),new int[]{0,1,3})) throw new RuntimeException(\"case\");"},
    "Bellman-Ford": {"python": "bellmanFord(3,[[0,1,4],[0,2,5],[1,2,-2]],0) == [0,4,2]", "java": "if(!Arrays.equals(s.bellmanFord(3,new int[][]{{0,1,4},{0,2,5},{1,2,-2}},0),new int[]{0,4,2})) throw new RuntimeException(\"case\");"},
    "Kruskal MST": {"python": "kruskalWeight([[0,1,1],[1,2,2],[0,2,5]],3) == 3", "java": "if(s.kruskalWeight(new int[][]{{0,1,1},{1,2,2},{0,2,5}},3)!=3) throw new RuntimeException(\"case\");"},
    "Trie": {"python": "trieCheck() is True", "java": "if(!s.trieCheck()) throw new RuntimeException(\"case\");"},
}

ALGORITHM_STARTERS = {
    "Linear Search": ("def linearSearch(nums, target):\n    # Return the matching index, or -1.\n    pass", "public int linearSearch(int[] nums, int target) { return -1; }"),
    "Binary Search": ("def binarySearch(nums, target):\n    pass", "public int binarySearch(int[] nums, int target) { return -1; }"),
    "Bubble Sort": ("def bubbleSort(nums):\n    pass", "public int[] bubbleSort(int[] nums) { return nums; }"),
    "Selection Sort": ("def selectionSort(nums):\n    pass", "public int[] selectionSort(int[] nums) { return nums; }"),
    "Insertion Sort": ("def insertionSort(nums):\n    pass", "public int[] insertionSort(int[] nums) { return nums; }"),
    "Two Pointers": ("def twoSumSorted(nums, target):\n    pass", "public int[] twoSumSorted(int[] nums, int target) { return new int[0]; }"),
    "Stack": ("def isValid(s):\n    pass", "public boolean isValid(String s) { return false; }"),
    "Hash Map Lookup": ("def twoSum(nums, target):\n    pass", "public int[] twoSum(int[] nums, int target) { return new int[0]; }"),
    "Merge Sort": ("def mergeSort(nums):\n    pass", "public int[] mergeSort(int[] nums) { return nums; }"),
    "Quick Sort": ("def quickSort(nums):\n    pass", "public int[] quickSort(int[] nums) { return nums; }"),
    "Sliding Window": ("def maxWindow(nums, k):\n    pass", "public int maxWindow(int[] nums, int k) { return 0; }"),
    "Backtracking": ("def subsets(nums):\n    pass", "public List<List<Integer>> subsets(int[] nums) { return new ArrayList<>(); }"),
    "Longest Common Subsequence": ("def lcs(a, b):\n    pass", "public int lcs(String a, String b) { return 0; }"),
    "Dynamic Programming · Knapsack": ("def knapsack(items, capacity):\n    pass", "public int knapsack(int[][] items, int capacity) { return 0; }"),
    "Queue": ("def queueOrder():\n    # Enqueue 4, 7 then dequeue twice.\n    pass", "public int[] queueOrder() { return new int[0]; }"),
    "Linked List Reversal": ("def reverseList(values):\n    pass", "public int[] reverseList(int[] values) { return values; }"),
    "Tree DFS": ("def preorder(values):\n    pass", "public int[] preorder(int[] values) { return values; }"),
    "Tree BFS": ("def levelOrder(values):\n    pass", "public int[] levelOrder(int[] values) { return values; }"),
    "BST Search": ("def searchBST(values, target):\n    pass", "public int searchBST(int[] values, int target) { return -1; }"),
    "Heap / Priority Queue": ("def heapPeek(values):\n    pass", "public int heapPeek(int[] values) { return -1; }"),
    "Topological Sort": ("def topo(n, edges):\n    # Return a valid topological ordering.\n    pass", "public int[] topo(int n, int[][] edges) { return new int[0]; }\npublic boolean validTopo(int[] order,int n,int[][] edges) { return false; }"),
    "Union Find": ("def unionCheck():\n    # Verify union(0,1), while 2 remains separate.\n    pass", "public boolean unionCheck() { return false; }"),
    "Dijkstra": ("def dijkstra(graph, source):\n    pass", "public int[] dijkstra(int[][][] graph, int source) { return new int[0]; }"),
    "Bellman-Ford": ("def bellmanFord(n, edges, source):\n    pass", "public int[] bellmanFord(int n, int[][] edges, int source) { return new int[0]; }"),
    "Kruskal MST": ("def kruskalWeight(edges, n):\n    pass", "public int kruskalWeight(int[][] edges, int n) { return 0; }"),
    "Trie": ("def trieCheck():\n    # Insert 'step'; find('step') true and find('ste') false.\n    pass", "public boolean trieCheck() { return false; }"),
}

def execute_algorithm_tests(language, algorithm, source):
    suite = ALGORITHM_CASES.get(algorithm)
    if not suite:
        return {"available": False, "error": f"{language} test execution is not configured yet for {algorithm}. JavaScript tests remain available."}
    if len(source) > 32_000:
        return {"available": False, "error": "Solution source is too large (maximum 32 KB)."}
    if language not in ("Python", "Java"):
        compiler = "gcc" if language == "C" else "g++"
        return {"available": False, "error": f"{language} algorithm execution is not configured. C/C++ need a local compiler and matching harness."}
    try:
        with tempfile.TemporaryDirectory(prefix="stepwise-algo-") as folder:
            if language == "Python":
                path = Path(folder) / "solution.py"
                check = suite["python"]
                path.write_text(source + "\n_stepwise_ok = (" + check + ")\nprint('PASS' if _stepwise_ok else 'FAIL')\n", encoding="utf-8")
                result = subprocess.run([shutil.which("python") or os.sys.executable, "-I", str(path)], cwd=folder, capture_output=True, text=True, timeout=3, env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"})
            else:
                path = Path(folder) / "Main.java"
                fixture = suite["java"]
                imports = "\n".join(line for line in source.splitlines() if line.strip().startswith("import "))
                body = "\n".join(line for line in source.splitlines() if not line.strip().startswith("import "))
                path.write_text((imports + "\n" if imports else "") + "class Solution {\n" + body + "\n}\npublic class Main { public static void main(String[] args) { Solution s=new Solution(); " + fixture + " System.out.println(\"PASS\"); } }\n", encoding="utf-8")
                compiled = subprocess.run([shutil.which("javac") or "javac", str(path)], cwd=folder, capture_output=True, text=True, timeout=15)
                if compiled.returncode:
                    return {"available": True, "passed": False, "output": (compiled.stderr or compiled.stdout)[-5000:]}
                result = subprocess.run([shutil.which("java") or "java", "-Xmx128m", "-cp", folder, "Main"], cwd=folder, capture_output=True, text=True, timeout=3, env={"PATH": os.environ.get("PATH", ""), "JAVA_TOOL_OPTIONS": "-XX:MaxRAM=128m -Xss512k"})
            output = (result.stdout or "") + (result.stderr or "")
            if result.returncode == 0 and "PASS" in result.stdout.splitlines():
                return {"available": True, "passed": True, "results": ["All checks passed"]}
            return {"available": True, "passed": False, "output": output[-5000:] or "One or more tests failed."}
    except subprocess.TimeoutExpired:
        return {"available": True, "passed": False, "output": "Execution timed out."}
    except OSError as exc:
        return {"available": False, "error": f"Could not start local runner: {exc}"}
def execute_problem_tests(language, problem, source):
    if problem not in PROBLEM_TESTS:
        return {"available": False, "error": "No test suite is available for this problem."}
    if len(source) > 32_000:
        return {"available": False, "error": "Solution source is too large (maximum 32 KB)."}
    if language not in ("Python", "Java", "C", "C++"):
        return {"available": False, "error": "Choose Python, Java, C, or C++."}
    if language in ("C", "C++"):
        compiler = os.environ.get("C_COMPILER" if language == "C" else "CXX_COMPILER", "gcc" if language == "C" else "g++")
        if not shutil.which(compiler):
            return {"available": False, "error": f"{language} tests need a local compiler ({compiler}) on PATH. Install GCC/MinGW, then restart Stepwise."}
        return {"available": False, "error": "The C/C++ test harness is not configured for this problem yet."}
    total = len(PROBLEM_TESTS[problem])
    try:
        with tempfile.TemporaryDirectory(prefix="stepwise-tests-") as folder:
            if language == "Python":
                file = Path(folder) / "solution.py"
                file.write_text(_python_runner(problem, source), encoding="utf-8")
                command = [shutil.which("python") or os.sys.executable, "-I", str(file)]
                env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
            else:
                file = Path(folder) / "Main.java"
                file.write_text(_java_runner(problem, source), encoding="utf-8")
                compiled = subprocess.run([shutil.which("javac") or "javac", str(file)], cwd=folder, capture_output=True, text=True, timeout=15)
                if compiled.returncode:
                    return {"available": True, "passed": False, "total": total, "output": (compiled.stderr or compiled.stdout)[-6000:]}
                command = [shutil.which("java") or "java", "-Xmx128m", "-cp", folder, "Main"]
                env = {"PATH": os.environ.get("PATH", ""), "JAVA_TOOL_OPTIONS": "-XX:MaxRAM=128m -Xss512k"}
            result = subprocess.run(command, cwd=folder, capture_output=True, text=True, timeout=3, env=env)
            output = (result.stdout or "").strip()
            runner_lines = [line for line in output.splitlines() if line.startswith("STEPWISE_PASS:") or line.startswith("STEPWISE_FAIL:")]
            python_passed = language == "Python" and result.returncode == 0 and len(runner_lines) == total and all(line.startswith("STEPWISE_PASS:") for line in runner_lines)
            java_passed = language == "Java" and result.returncode == 0 and output.endswith("PASS")
            if python_passed or java_passed:
                return {"available": True, "passed": True, "total": total, "results": [f"Test {i} passed" for i in range(1, total+1)]}
            return {"available": True, "passed": False, "total": total, "output": ((result.stderr or "") + (result.stdout or ""))[-6000:] or "Solution failed the test cases."}
    except subprocess.TimeoutExpired:
        return {"available": True, "passed": False, "total": total, "output": "Execution timed out after 3 seconds."}
    except OSError as exc:
        return {"available": False, "error": f"Could not start the local runner: {exc}"}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status, value, headers=None):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, val in headers.items(): self.send_header(key, val)
        self.end_headers()
        self.wfile.write(payload)

    def body(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 16_384: return None
            return json.loads(self.rfile.read(size) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return None

    def session_user(self):
        cookie = self.headers.get("Cookie", "")
        match = re.search(r"(?:^|;\s*)loop_session=([a-f0-9]{64})(?:;|$)", cookie)
        if not match: return None
        token_hash = hashlib.sha256(match.group(1).encode()).hexdigest()
        with connect() as db:
            row = db.execute("SELECT u.id,u.name,u.email,u.language FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?", (token_hash, int(time.time()))).fetchone()
        return dict(row) if row else None

    def issue_session(self, user_id):
        token = secrets.token_hex(32)
        with connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (int(time.time()),))
            db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user_id, int(time.time()) + SESSION_SECONDS))
        return {"Set-Cookie": f"loop_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/verify":
            token = parse_qs(urlparse(self.path).query).get("token", [""])[0]
            digest = hashlib.sha256(token.encode()).hexdigest() if token else ""
            with connect() as db:
                row = db.execute("SELECT user_id FROM email_verification_tokens WHERE token_hash=? AND expires_at>?", (digest, int(time.time()))).fetchone()
                if not row: return self.send_json(400, {"error": "That verification link is invalid or expired. Request a new one."})
                db.execute("UPDATE users SET email_verified=1 WHERE id=?", (row["user_id"],))
                db.execute("DELETE FROM email_verification_tokens WHERE user_id=?", (row["user_id"],))
            return self.send_json(200, {"ok": True})
        if path == "/api/me":
            user = self.session_user()
            if not user: return self.send_json(200, {"user": None, "solved": []})
            with connect() as db:
                solved = [r[0] for r in db.execute("SELECT problem FROM solved_problems WHERE user_id=? ORDER BY solved_at", (user["id"],))]
                algorithms = [dict(r) for r in db.execute("SELECT algorithm,level,completed_at FROM algorithm_completions WHERE user_id=? ORDER BY completed_at", (user["id"],))]
                certificates = [dict(r) for r in db.execute("SELECT track,title,issued_at FROM certificates WHERE user_id=? ORDER BY issued_at DESC", (user["id"],))]
            return self.send_json(200, {"user": user, "solved": solved, "algorithms": algorithms, "certificates": certificates})
        if path.startswith("/api/"):
            return self.send_json(404, {"error": "Not found"})
        if path == "/": self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.body()
        if data is None: return self.send_json(400, {"error": "Invalid request body"})
        if path in ("/api/register", "/api/login"):
            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
                return self.send_json(400, {"error": "Enter a valid email address."})
            if path.endswith("register"):
                name = str(data.get("name", "")).strip()
                if not name or len(name) > 60: return self.send_json(400, {"error": "Name must be between 1 and 60 characters."})
                if len(password) < 10: return self.send_json(400, {"error": "Use a password with at least 10 characters."})
                salt = secrets.token_bytes(16)
                try:
                    with connect() as db:
                        cur = db.execute("INSERT INTO users(name,email,password_hash,password_salt,email_verified) VALUES(?,?,?,?,0)", (name, email, derive(password, salt), salt.hex()))
                        user_id = cur.lastrowid
                except sqlite3.IntegrityError:
                    return self.send_json(409, {"error": "An account with that email already exists. Sign in or resend verification."})
                sent = send_verification(user_id, email)
                return self.send_json(201, {"ok": True, "mailSent": sent, "message": "Verification email sent." if sent else "Account created, but email delivery is not configured or unavailable. Ask the app owner to configure SMTP, then resend verification."})
            with connect() as db:
                row = db.execute("SELECT id,password_hash,password_salt,email_verified FROM users WHERE email=?", (email,)).fetchone()
            if not row or not hmac.compare_digest(derive(password, bytes.fromhex(row["password_salt"])), row["password_hash"]):
                return self.send_json(401, {"error": "Email or password is incorrect."})
            if not row["email_verified"]:
                return self.send_json(403, {"error": "Please verify your email first. Use Resend verification to get a fresh link."})
            return self.send_json(200, {"ok": True}, self.issue_session(row["id"]))
        if path == "/api/resend-verification":
            if not mail_configured(): return self.send_json(503, {"error": "Email delivery is not configured on this server yet."})
            email = str(data.get("email", "")).strip().lower()
            with connect() as db:
                row = db.execute("SELECT id,email,email_verified FROM users WHERE email=?", (email,)).fetchone()
            if row and not row["email_verified"]: send_verification(row["id"], row["email"])
            return self.send_json(200, {"ok": True, "message": "If that account needs verification, an email has been sent."})
        if path == "/api/forgot-password":
            if not mail_configured(): return self.send_json(503, {"error": "Email delivery is not configured on this server yet."})
            email = str(data.get("email", "")).strip().lower()
            with connect() as db:
                row = db.execute("SELECT id,email,email_verified FROM users WHERE email=?", (email,)).fetchone()
            if row and row["email_verified"]: send_reset(row["id"], row["email"])
            return self.send_json(200, {"ok": True, "message": "If a verified account uses that email, a reset link has been sent."})
        if path == "/api/reset-password":
            token = str(data.get("token", ""))
            password = str(data.get("password", ""))
            if len(password) < 10: return self.send_json(400, {"error": "Use a password with at least 10 characters."})
            digest = hashlib.sha256(token.encode()).hexdigest() if token else ""
            with connect() as db:
                row = db.execute("SELECT user_id FROM password_reset_tokens WHERE token_hash=? AND expires_at>?", (digest, int(time.time()))).fetchone()
                if not row: return self.send_json(400, {"error": "That reset link is invalid or expired. Request another one."})
                salt = secrets.token_bytes(16)
                db.execute("UPDATE users SET password_hash=?,password_salt=? WHERE id=?", (derive(password, salt), salt.hex(), row["user_id"]))
                db.execute("DELETE FROM password_reset_tokens WHERE user_id=?", (row["user_id"],))
                db.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
            return self.send_json(200, {"ok": True})
        if path == "/api/run-tests":
            language = str(data.get("language", ""))
            problem = str(data.get("problem", ""))
            source = str(data.get("source", ""))
            return self.send_json(200, execute_problem_tests(language, problem, source))
        if path == "/api/run-algorithm-tests":
            language = str(data.get("language", ""))
            algorithm = str(data.get("algorithm", ""))
            source = str(data.get("source", ""))
            return self.send_json(200, execute_algorithm_tests(language, algorithm, source))
        if path == "/api/logout":
            user = self.session_user()
            if user:
                token = re.search(r"(?:^|;\s*)loop_session=([a-f0-9]{64})(?:;|$)", self.headers.get("Cookie", ""))
                if token:
                    with connect() as db: db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.group(1).encode()).hexdigest(),))
            return self.send_json(200, {"ok": True}, {"Set-Cookie": "loop_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
        user = self.session_user()
        if not user: return self.send_json(401, {"error": "Please sign in to save your progress."})
        if path == "/api/solved":
            problem = str(data.get("problem", ""))
            if problem not in PROBLEM_CATALOG: return self.send_json(400, {"error": "Choose a problem from the catalog."})
            with connect() as db:
                db.execute("INSERT OR IGNORE INTO solved_problems(user_id,problem) VALUES(?,?)", (user["id"], problem))
                count = db.execute("SELECT COUNT(*) FROM solved_problems WHERE user_id=? AND problem IN (" + ",".join("?" for _ in PROBLEM_CATALOG) + ")", (user["id"], *sorted(PROBLEM_CATALOG))).fetchone()[0]
                if count == len(PROBLEM_CATALOG): db.execute("INSERT OR IGNORE INTO certificates(user_id,track,title) VALUES(?,?,?)", (user["id"], "problem-solving", "Problem Solving Foundations"))
            return self.send_json(200, {"ok": True, "completed": count == len(PROBLEM_CATALOG)})
        if path == "/api/algorithm-complete":
            algorithm = str(data.get("algorithm", "")).strip()
            level = str(data.get("level", "")).strip()
            if not algorithm or len(algorithm) > 100 or level not in ("Beginner", "Intermediate", "Advanced"):
                return self.send_json(400, {"error": "Invalid algorithm completion."})
            title = f"Algorithm Practice — {algorithm}"
            with connect() as db:
                db.execute("INSERT OR IGNORE INTO algorithm_completions(user_id,algorithm,level) VALUES(?,?,?)", (user["id"], algorithm, level))
                db.execute("INSERT OR IGNORE INTO certificates(user_id,track,title) VALUES(?,?,?)", (user["id"], "algorithm-practice", title))
            return self.send_json(200, {"ok": True, "title": title})
        if path == "/api/profile":
            name = str(data.get("name", "")).strip()
            language = str(data.get("language", "JavaScript"))
            if not name or len(name) > 60: return self.send_json(400, {"error": "Name must be between 1 and 60 characters."})
            if language not in ("JavaScript", "Python", "Java", "C", "C++"): return self.send_json(400, {"error": "Choose JavaScript, Python, Java, C, or C++."})
            with connect() as db: db.execute("UPDATE users SET name=?,language=? WHERE id=?", (name, language, user["id"]))
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "Not found"})

if __name__ == "__main__":
    initialize()
    port = int(os.environ.get("PORT", "8000"))
    print(f"Stepwise is running at http://127.0.0.1:{port}")
    print(f"SQLite database: {DB_PATH}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
