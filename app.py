import html
import os
import re
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    Response,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash
import markdown
import bleach

try:
    import psycopg
    from psycopg.rows import dict_row
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_PATH = os.environ.get("DB_PATH", "fydelistech.db")

ALLOW_REGISTER = os.environ.get("ALLOW_REGISTER", "true").strip().lower() in ("1", "true", "yes")
REGISTER_TOKEN = os.environ.get("REGISTER_TOKEN", "").strip()

ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + [
    "p",
    "br",
    "hr",
    "pre",
    "code",
    "h1",
    "h2",
    "h3",
    "h4",
    "blockquote",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "img",
    "div",
    "span",
    "ul",
    "ol",
    "li",
    "strong",
    "em",
    "del",
]

ALLOWED_ATTRIBUTES = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    "img": ["src", "alt", "title", "width", "height", "style"],
    "div": ["style", "align"],
    "p": ["style", "align"],
    "th": ["align", "style"],
    "td": ["align", "style"],
    "code": ["class"],
    "pre": ["class"],
    "a": ["href", "title", "target", "rel"],
}

ALLOWED_PROTOCOLS = ["http", "https", "data"]


class DBConnection:
    """Wrapper simples para aceitar placeholders '?' tanto no PostgreSQL quanto no SQLite."""

    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        if self.is_pg:
            if not HAS_PSYCOPG:
                raise RuntimeError("Instale 'psycopg[binary]' no requirements.txt para usar PostgreSQL.")
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            db_dir = os.path.dirname(DB_PATH)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row

    def _sql(self, query: str) -> str:
        if self.is_pg:
            return query.replace("?", "%s")
        return query

    def execute(self, query: str, params=()):
        sql = self._sql(query)
        if self.is_pg:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            return cur
        return self.conn.execute(sql, params)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.close()


def get_db():
    return DBConnection()


def init_db():
    with get_db() as conn:
        if conn.is_pg:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS posts (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    subtitle TEXT,
                    category TEXT NOT NULL,
                    tags TEXT,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
        else:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    subtitle TEXT,
                    category TEXT NOT NULL,
                    tags TEXT,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

        row = conn.execute("SELECT COUNT(*) AS cnt FROM posts").fetchone()
        count = row["cnt"] if conn.is_pg else row[0]
        if count == 0:
            conn.execute(
                """
                INSERT INTO posts (title, subtitle, category, tags, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "FydelisTechOS: Markdown, Tabelas e Arquitetura Bare-Metal",
                    "Notas técnicas sobre desenvolvimento x86_64, FydelTerm, FYFIRE e fluxo de publicação.",
                    "Kernel & Assembly",
                    "x86_64, NASM, Markdown, FydelisTechOS",
                    "Bem-vindo ao portal **FydelisTechOS**.\n\n"
                    "Agora o editor suporta **Markdown** completo, *itálico*, listas, **tabelas**, imagens e alinhamento.\n\n"
                    "### Exemplo de Tabela de Módulos\n\n"
                    "| Módulo | Linguagem | Função |\n"
                    "| :--- | :--- | :--- |\n"
                    "| FydelTerm | Assembly / C | Terminal nativo |\n"
                    "| FYFIRE | Assembly / C | Firewall do sistema |\n"
                    "| FYCRYPTO | Assembly / C | Criptografia nativa |\n\n"
                    "### Exemplo em x86_64 NASM\n\n"
                    "```nasm\n"
                    "section .text\n"
                    "global _start\n"
                    "_start:\n"
                    "    cli\n"
                    "    mov rsp, stack_top\n"
                    "    call kernel_main\n"
                    "    hlt\n"
                    "```\n",
                    datetime.now().strftime("%d/%m/%Y %H:%M"),
                ),
            )


init_db()


def users_count():
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
        return row["cnt"] if conn.is_pg else row[0]


def can_register():
    if users_count() == 0:
        return True
    if not ALLOW_REGISTER:
        return False
    if REGISTER_TOKEN:
        token = request.args.get("token", "") or request.form.get("token", "")
        return token == REGISTER_TOKEN
    return True


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Faça login para acessar o editor de publicações.", "error")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/robots.txt")
def robots_txt():
    base_url = request.url_root.rstrip("/")
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /login\n"
        "Disallow: /cadastro\n"
        "Disallow: /novo\n"
        "Disallow: /editar/\n"
        "Disallow: /excluir/\n"
        f"Sitemap: {base_url}/sitemap.xml\n"
    )
    return Response(content, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    base_url = html.escape(request.url_root.rstrip("/"))
    with get_db() as conn:
        posts = conn.execute("SELECT id, created_at FROM posts ORDER BY id DESC").fetchall()

    urls = [
        f"  <url><loc>{base_url}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>"
    ]
    for p in posts:
        lastmod_tag = ""
        try:
            dt = datetime.strptime(p["created_at"], "%d/%m/%Y %H:%M")
            lastmod_tag = f"<lastmod>{dt.strftime('%Y-%m-%d')}</lastmod>"
        except (ValueError, TypeError):
            pass

        urls.append(
            f"  <url><loc>{base_url}/post/{p['id']}</loc>{lastmod_tag}<changefreq>weekly</changefreq><priority>0.8</priority></url>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + "\n</urlset>"
    )
    return Response(xml, mimetype="application/xml")


@app.route("/cadastro", methods=["GET", "POST"])
def register():
    if not can_register():
        flash("Cadastro desativado ou token inválido.", "error")
        return redirect(url_for("login"))

    token_param = request.args.get("token", "") or request.form.get("token", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        cipher_method = request.form.get("cipher_method", "scrypt")

        if len(username) < 3:
            flash("O usuário deve ter pelo menos 3 caracteres.", "error")
            return render_template("register.html", token=token_param)

        if len(password) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.", "error")
            return render_template("register.html", token=token_param)

        if password != password_confirm:
            flash("As senhas não conferem.", "error")
            return render_template("register.html", token=token_param)

        method = "pbkdf2:sha256" if cipher_method == "pbkdf2" else "scrypt"
        password_hash = generate_password_hash(password, method=method)

        try:
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (username, password_hash, datetime.now().strftime("%d/%m/%Y %H:%M")),
                )
        except Exception:
            flash("Esse nome de usuário já está em uso.", "error")
            return render_template("register.html", token=token_param)

        flash("Conta criada com senha criptografada! Faça login para postar.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", token=token_param)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.args.get("next") or url_for("index")

        with get_db() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["logged_in"] = True
            session["username"] = user["username"]
            flash("Sessão iniciada com sucesso.", "success")
            return redirect(next_url)
        else:
            flash("Usuário ou senha inválidos.", "error")

    return render_template("login.html", can_register=can_register(), register_token=REGISTER_TOKEN)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Sessão encerrada.", "success")
    return redirect(url_for("index"))


@app.route("/")
def index():
    category = request.args.get("categoria", "")
    search = request.args.get("q", "").strip()

    query = "SELECT * FROM posts WHERE 1=1"
    params = []

    if category:
        query += " AND category = ?"
        params.append(category)

    if search:
        query += " AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term, like_term])

    query += " ORDER BY id DESC"

    with get_db() as conn:
        posts = conn.execute(query, params).fetchall()
        categories = [
            row["category"]
            for row in conn.execute("SELECT DISTINCT category FROM posts").fetchall()
        ]

    return render_template(
        "index.html",
        posts=posts,
        categories=categories,
        active_category=category,
        search=search,
    )


@app.route("/post/<int:post_id>")
def view_post(post_id):
    with get_db() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        flash("Publicação não encontrada.", "error")
        return redirect(url_for("index"))
    return render_template("post.html", post=post)


@app.route("/novo", methods=["GET", "POST"])
@login_required
def create_post():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subtitle = request.form.get("subtitle", "").strip()
        category = request.form.get("category", "Artigos").strip()
        tags = request.form.get("tags", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Título e conteúdo são obrigatórios.", "error")
            return render_template("editor.html", post=request.form, mode="create")

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO posts (title, subtitle, category, tags, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    subtitle,
                    category,
                    tags,
                    content,
                    datetime.now().strftime("%d/%m/%Y %H:%M"),
                ),
            )

        flash("Publicação gravada com sucesso!", "success")
        return redirect(url_for("index"))

    return render_template("editor.html", post=None, mode="create")


@app.route("/editar/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    with get_db() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

    if not post:
        flash("Publicação não encontrada.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subtitle = request.form.get("subtitle", "").strip()
        category = request.form.get("category", "Artigos").strip()
        tags = request.form.get("tags", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Título e conteúdo são obrigatórios.", "error")
            return render_template("editor.html", post=request.form, mode="edit")

        with get_db() as conn:
            conn.execute(
                """
                UPDATE posts
                SET title = ?, subtitle = ?, category = ?, tags = ?, content = ?
                WHERE id = ?
                """,
                (title, subtitle, category, tags, content, post_id),
            )

        flash("Publicação atualizada!", "success")
        return redirect(url_for("view_post", post_id=post_id))

    return render_template("editor.html", post=post, mode="edit")


@app.route("/excluir/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    with get_db() as conn:
        conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    flash("Publicação removida.", "success")
    return redirect(url_for("index"))


@app.template_filter("render_markdown")
def render_markdown(text):
    html_output = markdown.markdown(
        text or "",
        extensions=["fenced_code", "tables", "nl2br", "sane_lists"],
    )
    clean_html = bleach.clean(
        html_output,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    return clean_html


@app.template_filter("first_image")
def first_image(text):
    if not text:
        return ""
    md_match = re.search(r"!\[[^\]]*\]\((https?://[^\s\)]+)\)", text)
    if md_match:
        return md_match.group(1)
    html_match = re.search(r'<img[^>]+src=["\'](https?://[^"\']+)["\']', text, flags=re.IGNORECASE)
    if html_match:
        return html_match.group(1)
    return ""


@app.template_filter("clean_excerpt")
def clean_excerpt(text, limit=140):
    if not text:
        return ""
    cleaned = re.sub(r"!\[[^\]]*\]\([^\)]*\)", "", text)
    cleaned = re.sub(r"```.*?```", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"[#>*`]+", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rsplit(" ", 1)[0] + "..."


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
