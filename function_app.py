import azure.functions as func
import datetime
import json
import logging
import jwt
import uuid

# Secret key for JWT signing (Replace this with an environment variable in production)
SECRET_KEY = "gdtftu123r4u768ugvcxseuik"

# In-memory session storage (Use Redis or DB for production)
sessions = {}

app = func.FunctionApp()

### **🔹 User Sign-Up Endpoint**
@app.route(route="signup", auth_level=func.AuthLevel.Anonymous, methods=["POST"])
def sign_up(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing user sign-up request.")

    try:
        req_body = req.get_json()
        email = req_body.get("email")
        password = req_body.get("password")

        if not email or not password:
            return func.HttpResponse(json.dumps({"error": "Email and password are required"}), status_code=400)

        # Store user session (Replace with DB storage in production)
        if email in sessions:
            return func.HttpResponse(json.dumps({"error": "User already exists"}), status_code=409)

        user_id = str(uuid.uuid4())  # Generate unique user ID
        sessions[email] = {"user_id": user_id, "password": password, "created_at": str(datetime.datetime.utcnow())}

        return func.HttpResponse(json.dumps({"message": "User signed up successfully"}), status_code=201)

    except Exception as e:
        logging.error(f"Error during sign-up: {str(e)}")
        return func.HttpResponse(json.dumps({"error": "Internal Server Error"}), status_code=500)


### **🔹 User Sign-In Endpoint**
@app.route(route="login", auth_level=func.AuthLevel.Anonymous, methods=["POST"])
def login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing user login request.")

    try:
        req_body = req.get_json()
        email = req_body.get("email")
        password = req_body.get("password")

        if not email or not password:
            return func.HttpResponse(json.dumps({"error": "Email and password are required"}), status_code=400)

        # Authenticate user
        user_data = sessions.get(email)
        if not user_data or user_data["password"] != password:
            return func.HttpResponse(json.dumps({"error": "Invalid credentials"}), status_code=401)

        # Generate JWT Token
        payload = {
            "user_id": user_data["user_id"],
            "email": email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),  # Token expires in 2 hours
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        return func.HttpResponse(json.dumps({"message": "Login successful", "token": token}), status_code=200)

    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return func.HttpResponse(json.dumps({"error": "Internal Server Error"}), status_code=500)


### **🔹 Protected Route (Example)**
@app.route(route="protected", auth_level=func.AuthLevel.Anonymous, methods=["GET"])
def protected(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing protected route access.")

    token = req.headers.get("Authorization")
    if not token:
        return func.HttpResponse(json.dumps({"error": "Authorization token required"}), status_code=401)

    try:
        token = token.replace("Bearer ", "")  # Remove Bearer prefix if present
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return func.HttpResponse(json.dumps({"message": "Access granted", "user": decoded}), status_code=200)

    except jwt.ExpiredSignatureError:
        return func.HttpResponse(json.dumps({"error": "Token expired"}), status_code=401)
    except jwt.InvalidTokenError:
        return func.HttpResponse(json.dumps({"error": "Invalid token"}), status_code=401)