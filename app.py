import html
import os
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

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

ADMIN_USER = os.environ.get("ADMIN_USER", "").strip()
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH", "").strip()

if not ADMIN_PASS_HASH and ADMIN_PASS:
    ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)

DB_PATH = os.environ.get("DB_PATH", "fydelistech.db")

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


def get_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
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
        count = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
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
        conn.commit()


# Garante inicialização mesmo rodando via Gunicorn no Render
init_db()


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


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.args.get("next") or url_for("index")

        if not ADMIN_USER or not ADMIN_PASS_HASH:
            flash("Credenciais de administrador não configuradas no ambiente.", "error")
            return render_template("login.html")

        if username == ADMIN_USER and check_password_hash(ADMIN_PASS_HASH, password):
            session["logged_in"] = True
            session["username"] = username
            flash("Sessão iniciada com sucesso.", "success")
            return redirect(next_url)
        else:
            flash("Usuário ou senha inválidos.", "error")

    return render_template("login.html")


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
            conn.commit()

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
            conn.commit()

        flash("Publicação atualizada!", "success")
        return redirect(url_for("view_post", post_id=post_id))

    return render_template("editor.html", post=post, mode="edit")


@app.route("/excluir/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    with get_db() as conn:
        conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        conn.commit()
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
