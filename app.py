from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Tuple

from flask import Flask, render_template, request, abort, url_for, redirect, session
from pathlib import Path
import json
import re
import unicodedata

from validation import validate_payment_form
from encryption import hash_password, verify_password, encrypt_aes, decrypt_aes, obfuscate_card_number
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "dev-secret-change-me"

# Clave global para AES (16 bytes para AES-128)
AES_KEY = get_random_bytes(16)


BASE_DIR = Path(__file__).resolve().parent
EVENTS_PATH = BASE_DIR / "data" / "events.json"
USERS_PATH = BASE_DIR / "data" / "users.json"
ORDERS_PATH = BASE_DIR / "data" / "orders.json"
CATEGORIES = ["All", "Music", "Tech", "Sports", "Business"]
CITIES = ["Any", "New York", "San Francisco", "Berlin", "London", "Oakland", "San Jose"]


# ---------- security globals ------------
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_MINUTES = 5
# in-memory state for login attempts and lockout
login_state: Dict[str, dict] = {}

# ----------------------------------------


@dataclass(frozen=True)
class Event:
    id: int
    title: str
    category: str  
    city: str
    venue: str
    start: datetime
    end: datetime
    price_usd: float
    available_tickets: int
    banner_url: str
    description: str

def _user_with_defaults(u: dict) -> dict:
    u = dict(u)
    u.setdefault("role", "user")      
    u.setdefault("status", "active")  
    u.setdefault("locked_until", "") 
    return u

def get_current_user() -> Optional[dict]:
    email = session.get("user_email")
    if not email:
        return None
    return find_user_by_email(email)



def load_events() -> List[Event]:
    data = json.loads(EVENTS_PATH.read_text(encoding="utf-8"))
    return [
        Event(
            id=int(e["id"]),
            title=e["title"],
            category=e["category"],
            city=e["city"],
            venue=e["venue"],
            start=datetime.fromisoformat(e["start"]),
            end=datetime.fromisoformat(e["end"]),
            price_usd=float(e["price_usd"]),
            available_tickets=int(e["available_tickets"]),
            banner_url=e.get("banner_url", ""),
            description=e.get("description", ""),
        )
        for e in data
    ]


EVENTS: List[Event] = load_events()


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parsea fecha estilo YYYY-MM-DD. Devuelve None si inválida."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None


# ----------------- helpers for user validation ----------------

def _normalize(value: str) -> str:
    """Normalize input using NFKC and strip whitespace (collapse multi spaces)."""
    return " ".join(unicodedata.normalize("NFKC", (value or "")).split())


def validate_full_name(name: str) -> Tuple[str, str]:
    name = (name or "").strip()
    name = " ".join(name.split())
    if len(name) < 2 or len(name) > 60:
        return "", "Full name must be between 2 and 60 characters."
    # letters (including accents), spaces, apostrophes, hyphens
    if not re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ '\-]+", name):
        return "", "Full name contains invalid characters."
    return name, ""


def validate_user_email(email: str) -> Tuple[str, str]:
    email = (email or "").strip().lower()
    if not email:
        return "", "Email is required."
    if len(email) > 254:
        return "", "Email must be 254 characters or fewer."
    parts = email.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1] or "." not in parts[1]:
        return "", "Email format is invalid."
    return email, ""


def validate_phone(phone: str) -> Tuple[str, str]:
    phone = (phone or "").strip()
    if not phone:
        return "", "Phone number is required."
    if not phone.isdigit():
        return "", "Phone must contain digits only."
    if len(phone) < 7 or len(phone) > 15:
        return "", "Phone number must be between 7 and 15 digits."
    return phone, ""


def validate_password(password: str, email: Optional[str] = None) -> Tuple[str, str]:
    password = password or ""
    if len(password) < 8 or len(password) > 64:
        return "", "Password must be 8–64 characters long."
    if " " in password:
        return "", "Password may not contain spaces."
    if not re.search(r"[A-Z]", password):
        return "", "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "", "Password must include a lowercase letter."
    if not re.search(r"[0-9]", password):
        return "", "Password must include a digit."
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}<>?]", password):
        return "", "Password must include a special character."
    if email and password.lower() == email.lower():
        return "", "Password may not be the same as your email."
    return password, ""


# ------------------ decorators & context --------------------
from functools import wraps

def require_login(role: Optional[str] = None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user.get("role") != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_user():
    # make current_user available in all templates
    return {"current_user": get_current_user()}


def _safe_int(value: str, default: int = 1, min_v: int = 1, max_v: int = 10) -> int:
    """Validación simple de enteros para inputs (cantidad, etc.)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, n))


def filter_events(
    q: str = "",
    city: str = "Any",
    date: Optional[datetime] = None,
    category: str = "All",
    ) -> List[Event]:
    q_norm = (q or "").strip().lower()
    city_norm = (city or "Any").strip()
    category_norm = (category or "All").strip()

    results = load_events()

    if category_norm != "All":
        results = [e for e in results if e.category == category_norm]

    if city_norm != "Any":
        results = [e for e in results if e.city == city_norm]

    if date:
        results = [
            e for e in results
            if e.start.date() == date.date()
        ]

    if q_norm:
        results = [
            e for e in results
            if q_norm in e.title.lower() or q_norm in e.venue.lower()
        ]

    results.sort(key=lambda e: e.start)
    return results


def get_event_or_404(event_id: int) -> Event:
    for e in EVENTS:
        if e.id == event_id:
            return e
    abort(404)


def load_users() -> list[dict]:
    if not USERS_PATH.exists():
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(USERS_PATH.read_text(encoding="utf-8"))


def save_users(users: list[dict]) -> None:
    USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")


def find_user_by_email(email: str) -> Optional[dict]:
    users = load_users()
    email_norm = (email or "").strip().lower()
    for u in users:
        if (u.get("email", "") or "").strip().lower() == email_norm:
            return u
    return None


def user_exists(email: str) -> bool:
    return find_user_by_email(email) is not None

def load_orders() -> list[dict]:
    if not ORDERS_PATH.exists():
        ORDERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        ORDERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(ORDERS_PATH.read_text(encoding="utf-8"))


def save_orders(orders: list[dict]) -> None:
    ORDERS_PATH.write_text(json.dumps(orders, indent=2), encoding="utf-8")


def next_order_id(orders: list[dict]) -> int:
    return max([o.get("id", 0) for o in orders], default=0) + 1

# -----------------------------
# Rutas
# -----------------------------
@app.get("/")
def index():
    q = request.args.get("q", "")
    city = request.args.get("city", "Any")
    date_str = request.args.get("date", "")
    category = request.args.get("category", "All")

    date = _parse_date(date_str)
    events = filter_events(q=q, city=city, date=date, category=category)

    featured = events[:3] 
    upcoming = events[:6]

    return render_template(
        "index.html",
        q=q,
        city=city,
        date_str=date_str,
        category=category,
        categories=CATEGORIES,
        cities=CITIES,
        featured=featured,
        upcoming=upcoming,
    )


@app.get("/event/<int:event_id>")
def event_detail(event_id: int):
    event = next((e for e in load_events() if e.id == event_id), None)
    if not event:
        abort(404)

    similar = [e for e in EVENTS if e.category == event.category and e.id != event.id][:5]

    return render_template(
        "event_detail.html",
        event=event,
        similar=similar,
    )


@app.post("/event/<int:event_id>/buy")
def buy_ticket(event_id: int):
    event = get_event_or_404(event_id) 
    qty = _safe_int(request.form.get("qty", "1"), default=1, min_v=1, max_v=8)

    if qty > event.available_tickets:
        similar = [e for e in load_events() if e.category == event.category and e.id != event.id][:5]
        return render_template(
            "event_detail.html",
            event=event,
            similar=similar,
            buy_error="Not enough tickets available for that quantity."
        ), 400

    return redirect(url_for("checkout", event_id=event.id, qty=qty))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        registered = request.args.get("registered")
        msg = "Account created successfully. Please sign in." if registered == "1" else None
        return render_template("login.html", info_message=msg)

    email = request.form.get("email", "")
    password = request.form.get("password", "")

    # basic field-level validation
    field_errors = {}
    if not email.strip():
        field_errors["email"] = "Email is required."
    if not password.strip():
        field_errors["password"] = "Password is required."
    # structure check for email
    if email.strip():
        _, err_email = validate_user_email(email)
        if err_email:
            field_errors["email"] = err_email

    # early return on field validation
    if field_errors:
        return render_template(
            "login.html",
            error="Please fix the highlighted fields.",
            field_errors=field_errors,
            form={"email": email},
        ), 400

    norm_email = email.strip().lower()
    now = datetime.utcnow()
    state = login_state.get(norm_email, {"attempts": 0, "locked_until": None})

    # merge any persistent lock information from user record
    user = find_user_by_email(norm_email)
    if user:
        lu = user.get("locked_until")
        if lu:
            try:
                locked_dt = datetime.fromisoformat(lu)
            except Exception:
                locked_dt = None
            if locked_dt:
                # if stored lock is later than in-memory state, update
                if not state.get("locked_until") or locked_dt > state.get("locked_until"):
                    state["locked_until"] = locked_dt
                    login_state[norm_email] = state

    # if previous lock expired, reset counters
    if state.get("locked_until") and now >= state["locked_until"]:
        state = {"attempts": 0, "locked_until": None}
        login_state[norm_email] = state
        # clear persisted value as well
        if user and user.get("locked_until"):
            users = load_users()
            for u in users:
                if (u.get("email") or "").strip().lower() == norm_email:
                    u["locked_until"] = ""
                    break
            save_users(users)

    # check if locked still active
    if state.get("locked_until") and now < state["locked_until"]:
        remaining = state["locked_until"] - now
        minutes = int(remaining.total_seconds() // 60) + 1
        return render_template(
            "login.html",
            error=f"Account locked. Try again in {minutes} minute(s).",
            field_errors={"email": " ", "password": " "},
            form={"email": email},
        ), 403

    user = find_user_by_email(norm_email)
    
    # Verificar credenciales: usuario existe Y contraseña es válida
    password_valid = False
    if user and isinstance(user.get("password"), dict):
        password_valid = verify_password(password, user.get("password"))
    
    if not user or not password_valid:
        # increment attempts
        state["attempts"] = state.get("attempts", 0) + 1
        if state["attempts"] > MAX_LOGIN_ATTEMPTS:
            lock_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            state["locked_until"] = lock_until
            # also persist to user record if exists
            if user:
                users = load_users()
                for u in users:
                    if (u.get("email") or "").strip().lower() == norm_email:
                        u["locked_until"] = lock_until.isoformat()
                        break
                save_users(users)
        login_state[norm_email] = state
        return render_template(
            "login.html",
            error="Invalid credentials.",
            field_errors={"email": " ", "password": " "},
            form={"email": email},
        ), 401
    # successful login: reset state and clear persisted lock
    login_state.pop(norm_email, None)
    if user.get("locked_until"):
        users = load_users()
        for u in users:
            if (u.get("email") or "").strip().lower() == norm_email:
                u["locked_until"] = ""
                break
        save_users(users)
    session["user_email"] = (user.get("email") or "").strip().lower()
    # store role for template logic (admin link, etc.)
    session["user_role"] = user.get("role", "user")

    # store login time for potential session expiration logic
    session["time_user_logged_in"] = datetime.now(timezone.utc)

    session["user_email"] = norm_email
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    full_name = request.form.get("full_name", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    field_errors = {}
    form_data = {"full_name": full_name, "email": email, "phone": phone}

    # validate each field
    clean_name, err = validate_full_name(full_name)
    if err:
        field_errors["full_name"] = err
    clean_email, err = validate_user_email(email)
    if err:
        field_errors["email"] = err
    elif user_exists(clean_email):
        field_errors["email"] = "This email is already registered."
    clean_phone, err = validate_phone(phone)
    if err:
        field_errors["phone"] = err
    clean_password, err = validate_password(password, email=clean_email)
    if err:
        field_errors["password"] = err
    if password != confirm_password:
        field_errors["confirm_password"] = "Passwords do not match."

    if field_errors:
        return render_template(
            "register.html",
            error="Please fix the highlighted fields.",
            field_errors=field_errors,
            form=form_data,
        ), 400

    # all good, persist
    users = load_users()
    next_id = max([u.get("id", 0) for u in users], default=0) + 1
    
    # Hash de la contraseña
    password_data = hash_password(clean_password)
    
    # Cifrado del teléfono
    phone_cifrado, phone_nonce, phone_tag = encrypt_aes(clean_phone, AES_KEY)
    
    users.append({
        "id": next_id,
        "full_name": clean_name,
        "email": clean_email,
        "phone": phone_cifrado,
        "phone_nonce": phone_nonce,
        "phone_tag": phone_tag,
        "password": password_data,
        "role": "user",
        "status": "active",
    })
    save_users(users)

    return redirect(url_for("login", registered="1"))

@app.get("/dashboard")
@require_login()
def dashboard():

    paid = request.args.get("paid") == "1"
    user = get_current_user()
    return render_template("dashboard.html", user_name=(user.get("full_name") if user else "User"), paid=paid)

@app.route("/checkout/<int:event_id>", methods=["GET", "POST"])
@require_login()
def checkout(event_id: int):

    if datetime.now(timezone.utc) - session.get("time_user_logged_in") > timedelta(minutes=3):
        session.clear()
        return redirect(url_for("login"))

    events = load_events()
    event = next((e for e in events if e.id == event_id), None)
    if not event:
        abort(404)

    qty = _safe_int(request.args.get("qty", "1"), default=1, min_v=1, max_v=8)

    service_fee = 5.00
    subtotal = event.price_usd * qty
    total = subtotal + service_fee

    if request.method == "GET":
        return render_template(
            "checkout.html",
            event=event,
            qty=qty,
            subtotal=subtotal,
            service_fee=service_fee,
            total=total,
            errors={},
            form_data={}
        )

    card_number = request.form.get("card_number", "")
    exp_date = request.form.get("exp_date", "")
    cvv = request.form.get("cvv", "")
    name_on_card = request.form.get("name_on_card", "")
    billing_email = request.form.get("billing_email", "")

    clean, errors = validate_payment_form(
        card_number=card_number,
        exp_date=exp_date,
        cvv=cvv,
        name_on_card=name_on_card,
        billing_email=billing_email
    )

    # Cifrar email de facturación
    email_cifrado, email_nonce, email_tag = encrypt_aes(clean.get("billing_email", ""), AES_KEY)
    

    form_data = {
        "exp_date": clean.get("exp_date", ""),
        "name_on_card": clean.get("name_on_card", ""),
        "billing_email": email_cifrado,
        "billing_email_nonce": email_nonce,
        "billing_email_tag": email_tag,
        "card": obfuscate_card_number(clean.get("card", "")),
    }

    if errors:
        return render_template(
            "checkout.html",
            event=event, qty=qty, subtotal=subtotal,
            service_fee=service_fee, total=total,
            errors=errors, form_data=clean
        ), 400

    orders = load_orders()
    order_id = next_order_id(orders)

    orders.append({
        "id": order_id,
        "user_email": session.get("user_email", ""),
        "event_id": event.id,
        "event_title": event.title,
        "qty": qty,
        "unit_price": event.price_usd,
        "service_fee": service_fee,
        "total": total,
        "status": "PAID",
        "created_at": datetime.utcnow().isoformat(),
        "payment": form_data
    })

    save_orders(orders)

    return redirect(url_for("dashboard", paid="1"))



@app.route("/profile", methods=["GET", "POST"])
@require_login()
def profile():

    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    
    if datetime.now(timezone.utc) - session.get("time_user_logged_in") > timedelta(minutes=3):
        session.clear()
        return redirect(url_for("login"))

    # Descifrar teléfono si está cifrado
    phone_display = user.get("phone", "")
    if user.get("phone_nonce"):
        try:
            phone_display = decrypt_aes(user.get("phone"), user.get("phone_nonce"), user.get("phone_tag"), AES_KEY)
        except:
            phone_display = "(encrypted)"

    form = {
        "full_name": user.get("full_name", ""),
        "email": user.get("email", ""),
        "phone": phone_display,
    }

    field_errors = {}  
    success_msg = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        phone = request.form.get("phone", "")

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_new_password = request.form.get("confirm_new_password", "")

        field_errors = {}

        # validate name and phone first
        clean_name, err = validate_full_name(full_name)
        if err:
            field_errors["full_name"] = err
        clean_phone, err = validate_phone(phone)
        if err:
            field_errors["phone"] = err

        # password change logic
        if new_password or confirm_new_password or current_password:
            # require current password
            if not current_password:
                field_errors["current_password"] = "Current password required to change password."
            elif not verify_password(current_password, user.get("password")):
                field_errors["current_password"] = "Current password is incorrect."

            # validate new password contents
            if new_password:
                clean_new, err = validate_password(new_password, email=user.get("email"))
                if err:
                    field_errors["new_password"] = err
            else:
                field_errors["new_password"] = "New password is required."

            if new_password != confirm_new_password:
                field_errors["confirm_new_password"] = "Passwords do not match."

        if field_errors:
            # preserve form values
            form["full_name"] = full_name
            form["phone"] = phone
            return render_template(
                "profile.html",
                form=form,
                field_errors=field_errors,
                success_message=None,
            ), 400

        # persist changes
        users = load_users()
        email_norm = (user.get("email") or "").strip().lower()

        for u in users:
            if (u.get("email") or "").strip().lower() == email_norm:
                u["full_name"] = clean_name
                
                # Cifrar teléfono
                phone_cifrado, phone_nonce, phone_tag = encrypt_aes(clean_phone, AES_KEY)
                u["phone"] = phone_cifrado
                u["phone_nonce"] = phone_nonce
                u["phone_tag"] = phone_tag
                
                if new_password:
                    u["password"] = hash_password(new_password)
                break

        save_users(users)

        form["full_name"] = clean_name
        form["phone"] = clean_phone
        success_msg = "Profile updated successfully."

    return render_template(
        "profile.html",
        form=form,
        field_errors=field_errors,
        success_message=success_msg,
    )
@app.get("/admin/users")
@require_login(role="admin")
def admin_users():

    if datetime.now(timezone.utc) - session.get("time_user_logged_in") > timedelta(minutes=3):
        session.clear()
        return redirect(url_for("login"))

    q = (request.args.get("q") or "").strip().lower()
    role = (request.args.get("role") or "all").strip().lower()
    status = (request.args.get("status") or "all").strip().lower()
    lockout = (request.args.get("lockout") or "all").strip().lower()

    users = [_user_with_defaults(u) for u in load_users()]

    # filtros
    if q:
        users = [
            u for u in users
            if q in (u.get("full_name","").lower()) or q in (u.get("email","").lower())
        ]

    if role != "all":
        users = [u for u in users if (u.get("role","user").lower() == role)]

    if status != "all":
        users = [u for u in users if (u.get("status","active").lower() == status)]

    if lockout != "all":
        if lockout == "locked":
            users = [u for u in users if (u.get("locked_until") or "").strip()]
        elif lockout == "not_locked":
            users = [u for u in users if not (u.get("locked_until") or "").strip()]

    users.sort(key=lambda u: (u.get("full_name","").lower(), u.get("id", 0)))

    return render_template(
        "admin_users.html",
        users=users,
        filters={"q": q, "role": role, "status": status, "lockout": lockout},
        total=len(users),
    )

@app.post("/admin/users/<int:user_id>/toggle")
@require_login(role="admin")
def admin_toggle_user(user_id: int):
    if datetime.now(timezone.utc) - session.get("time_user_logged_in") > timedelta(minutes=3):
        session.clear()
        return redirect(url_for("login"))
    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u.setdefault("status", "active")
            u["status"] = "disabled" if u["status"] == "active" else "active"
            break
    save_users(users)
    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/role")
@require_login(role="admin")
def admin_change_role(user_id: int):
    new_role = request.form.get("role", "user")

    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u["role"] = new_role
            break
    save_users(users)
    return redirect(url_for("admin_users"))

@app.route("/logout")
def logout():
    """Clear session and send user back to home page."""
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
