from flask import Flask
from flask import render_template
from flask import make_response
from flask import request
from flask import redirect
from util import validate_password
from util import generate_auth_token
from util import count_files_in_folder
from flask import jsonify
import bcrypt
import mysql.connector
import hashlib


app = Flask(__name__,static_url_path='/static')

@app.after_request
def add_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route("/")
def home():
    username="Guest"
    path="None"
    user_type_cookie = request.cookies.get('auth')
    if(user_type_cookie=="0" or user_type_cookie==0):
        user_type_cookie=None
    if user_type_cookie != None:
        try:
            conn = mysql.connector.connect(
                user = 'user',
                password = 'password',
                host = 'db',
                database = 'db'
            )
            cursor = conn.cursor()
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        query = "SELECT * FROM user"
        cursor.execute(query)
        result = cursor.fetchall()
        username =''
        print(result)
        for user in result:
            print(user)
            if(hashlib.sha256(user_type_cookie.encode('utf-8')).hexdigest() == user[3]):
                username = user[1]
                break
        conn.commit()
        create_table = "CREATE TABLE IF NOT EXISTS profiles (username TEXT, path TEXT)"
        cursor.execute(create_table)
        conn.commit()
        select = "SELECT * FROM profiles WHERE username=%s"
        values = (username,)
        cursor.execute(select,values)
        result = cursor.fetchall()
        if len(result) > 0:
            path = result[0][1]
        else:
            path = "../static/null.png"
        conn.commit()
        cursor.close()
        conn.close()
    if username == '':
        user_type_cookie = None
        path = "None"
    response = make_response(render_template('index.html',user_type=user_type_cookie,name=username,team="None",profile=path))
    response.headers['Content-Type'] = 'text/html'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route("/profile",methods=['POST'])
def profile():
    user_type_cookie = request.cookies.get('auth')
    if(user_type_cookie=="0" or user_type_cookie==0):
        user_type_cookie=None
    if user_type_cookie != None:
        try:
            conn = mysql.connector.connect(
                user = 'user',
                password = 'password',
                host = 'db',
                database = 'db'
            )
            cursor = conn.cursor()
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        query = "SELECT * FROM user"
        cursor.execute(query)
        result = cursor.fetchall()
        username =''
        print(result)
        for user in result:
            print(user)
            if(hashlib.sha256(user_type_cookie.encode('utf-8')).hexdigest() == user[3]):
                username = user[1]
                break
        conn.commit()
    if username == '':
        user_type_cookie = None
    #ADDING A NEW TABLE FOR ALL PROFILE PIC PATHS
    if 'profilePic' not in request.files:
        return 404, 'No file uploaded'
    else:
        file = request.files['profilePic']
        if file.filename =='':
            return 404,'No selected file'
        else:
            num = count_files_in_folder("../static/profiles")
            file_path = 'static/profiles/image' + str(num)
            file_bytes = file.read()
            with open(file_path, 'wb') as f:
                f.write(file_bytes)
            #putting in a sql table
            create_table = "CREATE TABLE IF NOT EXISTS profiles (username TEXT, path TEXT)"
            cursor.execute(create_table)
            conn.commit()
            query = "SELECT * FROM profiles WHERE username=%s"
            values = (username,)
            cursor.execute(query,values)
            result = cursor.fetchall()
            if len(result) > 0:
                update = "UPDATE profiles SET path=%s WHERE username=%s"
                values = (file_path,username)
                cursor.execute(update,values)
            else:
                insert = "INSERT INTO profiles (username,path) VALUES (%s,%s)"
                values = (username,file_path)
                cursor.execute(insert,values)
            conn.commit()
            cursor.close()
            conn.close()
            return redirect("/")
            
@app.route("/like",methods=['POST'])
def like():
    id = request.form.get('id')
    user_cookie = request.cookies.get('auth')
    if (user_cookie != 0 and user_cookie != '0' and user_cookie != None):
        try:
            conn = mysql.connector.connect(
                user = 'user',
                password = 'password',
                host = 'db',
                database = 'db'
            )
            cursor = conn.cursor()
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        query = "SELECT * FROM user"
        cursor.execute(query)
        result = cursor.fetchall()
        username =''
        for user in result:
            if(hashlib.sha256(user_cookie.encode('utf-8')).hexdigest() == user[3]):
                username = user[1]
                break
        #SETUP A TABLE FOR LIKES
        user_like_table = "CREATE TABLE IF NOT EXISTS user_likes (id INTEGER, username TEXT NOT NULL, like_count INTEGER);"
        cursor.execute(user_like_table)
        conn.commit()
        #check if already a record of liking
        query = "SELECT * FROM user_likes WHERE id=%s AND username=%s"
        values = (id, username)
        cursor.execute(query,values)
        result = cursor.fetchall()
        #if there already is a record of a like from this user on the specific message
        if len(result) != 0:
            new_value = 0
            current_value = result[0][2]
            if current_value == 1:
                new_value = 0
                query = "SELECT * FROM likes WHERE id=%s;"
                values = (id,)
                cursor.execute(query,values)
                result = cursor.fetchall()
                current = result[0][1]
                current = current - 1
                query = "UPDATE likes SET count=%s WHERE id=%s;"
                values = (current,id)
                cursor.execute(query,values)
                conn.commit()
            else:
                new_value = 1
                query = "SELECT * FROM likes WHERE id=%s;"
                values = (id,)
                cursor.execute(query,values)
                result = cursor.fetchall()
                current = result[0][1]
                current = current + 1
                query = "UPDATE likes SET count=%s WHERE id=%s;"
                values = (current,id)
                cursor.execute(query,values)
                conn.commit()
            query  = "UPDATE user_likes SET like_count=%s WHERE id=%s AND username=%s"
            values = (new_value, id, username)
            cursor.execute(query,values)
            conn.commit()
        else:
            query = "INSERT INTO user_likes (id,username,like_count) VALUES (%s,%s,%s);"
            values = (id,username,'1')
            cursor.execute(query,values)
            conn.commit()
            query = "SELECT * FROM likes WHERE id=%s;"
            values = (id,)
            cursor.execute(query,values)
            result = cursor.fetchall()
            current = result[0][1]
            current = current + 1
            query = "UPDATE likes SET count=%s WHERE id=%s;"
            values = (current,id)
            cursor.execute(query,values)
            conn.commit()
        response = jsonify({"message": "Success, like entered"})
    
    # Redirect to another route
        return redirect('/chat'), 302
    else:
        response = jsonify({"message": "Need to be logged in"})
    
    # Redirect to another route
        return redirect('/'), 302

@app.route("/chat-update")
def update_chat():
    try:
        conn = mysql.connector.connect(
            user = 'user',
            password = 'password',
            host = 'db',
            database = 'db'
        )
        cursor = conn.cursor()
    except mysql.connector.Error as e:
        print(f"Error: {e}")
    try:
        select_query = "SELECT * FROM messages"
        cursor.execute(select_query)
        result = cursor.fetchall()
        like_query = "SELECT * FROM likes"
        cursor.execute(like_query)
        result2 = cursor.fetchall()
    except:
        result = []
        result2 = []
    conn.commit()
    cursor.close()
    conn.close()
    data  = {
        'messages':result,
        'likes':result2
    }
    response = jsonify(data)
    return response

@app.route("/chat-message",methods=['POST'])
def chat_message():
    username="Guest"
    username = request.form.get('username')
    team = request.form.get('team')
    message = request.form.get('message')
    user_type_cookie = request.cookies.get('auth')
    if(user_type_cookie=="0" or user_type_cookie==0):
        user_type_cookie=None
    if user_type_cookie != None:
        try:
            conn = mysql.connector.connect(
                user = 'user',
                password = 'password',
                host = 'db',
                database = 'db'
            )
            cursor = conn.cursor()
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        query = "SELECT * FROM user"
        cursor.execute(query)
        result = cursor.fetchall()
        username =''
        for user in result:
            if(hashlib.sha256(user_type_cookie.encode('utf-8')).hexdigest() == user[3]):
                username = user[1]
                break
        if(username!="Guest"):
            #CREATING THE MESSAGES TABLE THAT EACH HAVE A SPECIFIC ID
            create_table = "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTO_INCREMENT,username TEXT NOT NULL,team TEXT NOT NULL,message TEXT NOT NULL);"
            cursor.execute(create_table)
            conn.commit()
            #CREATING THE LIKE TABLE THAT WILL USE THE SPECIFIC ID AND HAVE LIKE COUNTER
            create_like_table = "CREATE TABLE IF NOT EXISTS likes (id INTEGER PRIMARY KEY, count INTEGER);"
            cursor.execute(create_like_table)
            conn.commit()
            #INSERTING A MESSAGE
            insert_query = "INSERT INTO messages (username, team,message) VALUES (%s,%s,%s);"
            values = (username, team, message)
            cursor.execute(insert_query, values)
            conn.commit()
            #TAKING THE NEW MESSAGE ID AND ESTABLISHING ZERO LIKES IN LIKE TABLE
            last_inserted_id = cursor.lastrowid
            insert_likes = "INSERT INTO likes (id, count) VALUES (%s,%s);"
            values = (last_inserted_id,'0')
            cursor.execute(insert_likes, values)
            conn.commit()
        conn.commit()
        cursor.close()
        conn.close()
        return redirect('/chat')
    else:
        return redirect("/")

@app.route("/chat",methods=['POST','GET'])
def chat():
    if request.method == 'POST' or request.method == 'GET':
        if request.method == 'POST':
            username = request.form.get('name')
            team = request.form.get('team')
            profile = request.form.get('profile')
        else:
            user_type_cookie = request.cookies.get('auth')
            if(user_type_cookie=="0" or user_type_cookie==0 or user_type_cookie==None):
                user_type_cookie=None
                response = jsonify({"message": "Need to be logged in"})
                return redirect('/'), 302

            if user_type_cookie != None:
                try:
                    conn = mysql.connector.connect(
                        user = 'user',
                        password = 'password',
                        host = 'db',
                        database = 'db'
                    )
                    cursor = conn.cursor()
                except mysql.connector.Error as e:
                    print(f"Error: {e}")
                query = "SELECT * FROM user"
                cursor.execute(query)
                result = cursor.fetchall()
                username =''
                team = 'None'
                for user in result:
                    if(hashlib.sha256(user_type_cookie.encode('utf-8')).hexdigest() == user[3]):
                        username = user[1]
                        break
            #user_query = "SELECT * FROM user WHERE auth_token=%s"
            #values = (user_type_cookie,)
            #cursor.execute(user_query,values)
            #result = cursor.fetchall()
            #username = result[0][1]
            #team = 'None'
        try:
            conn = mysql.connector.connect(
                user = 'user',
                password = 'password',
                host = 'db',
                database = 'db'
            )
            cursor = conn.cursor()
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        try:
            select_query = "SELECT * FROM messages"
            cursor.execute(select_query)
            result = cursor.fetchall()
        except:
            result = []
        conn.commit()
        cursor.close()
        conn.close()
        response = make_response(render_template('chat.html',name=username,team=team,messages=result,profile=profile))
        response.headers['Content-ype'] = 'text/html'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
        
        
@app.route("/register", methods=['POST'])
def register():
    username = request.form.get('reg-username')
    password = request.form.get('reg-password')
    confirm_password = request.form.get('reg-confirm')
    try:
        conn = mysql.connector.connect(
            user = 'user',
            password = 'password',
            host = 'db',
            database = 'db'
        )
        cursor = conn.cursor()
    except mysql.connector.Error as e:
        print(f"Error: {e}")
    create_table_query = """CREATE TABLE IF NOT EXISTS user (
        id INT AUTO_INCREMENT PRIMARY KEY, 
        username VARCHAR(255) NOT NULL, 
        password VARCHAR(255) NOT NULL,
        auth_token VARCHAR(255) NOT NULL
        );"""
    cursor.execute(create_table_query)
    conn.commit()
    unique_username_query = "SELECT * FROM user WHERE username=%s"
    values = (username,)
    cursor.execute(unique_username_query,values)
    result = cursor.fetchall()
    if(len(result)!=0):
        print("Need a unique username")
        return "Error: Username must be unique", 400
    else:
        if(password == confirm_password):
            if (len(validate_password(password))==0):
                auth_token = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
                hash = auth_token.decode('utf-8')
                safe_username = username.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                register_query = "INSERT INTO user (username, password, auth_token) VALUES(%s,%s,%s)"
                values = (safe_username,hash,"0")
                cursor.execute(register_query,values)
                conn.commit()
                cursor.close()
                conn.close()
                response = make_response(render_template('index.html'))
                response.headers['Content-Type'] = 'text/html'
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['Location'] = '/'
                response.status_code = 302
                return response
            else:
                register_error = "Password too weak. Look at requirements and try again."
                return render_template('index.html', register_error=register_error)
        else:
            register_error = "Passwords do not match. Try again."
            return render_template('index.html', register_error=register_error)


@app.route("/login",methods=['POST'])          
def login():
    username = request.form.get('log-username')
    password = request.form.get('log-password')
    try:
        conn = mysql.connector.connect(
            user = 'user',
            password = 'password',
            host = 'db',
            database = 'db'
        )
        cursor = conn.cursor()
    except mysql.connector.Error as e:
        print(f"Error: {e}")
    check_account_query = "SELECT * FROM user WHERE username=%s"
    values = (username,)
    cursor.execute(check_account_query,values)
    result = cursor.fetchall()
    if result:
        hashed_password = result[0][2]
        if(bcrypt.checkpw(password.encode("utf-8"),hashed_password.encode("utf-8"))):
            auth_token = generate_auth_token(32)
            h = hashlib.sha256(auth_token.encode('utf-8')).hexdigest()
            print(h)
            insert_auth_query = "UPDATE user SET auth_token=%s WHERE username=%s"
            values = (h,username)
            cursor.execute(insert_auth_query,values)
            conn.commit()
            cursor.close()
            conn.close()
            response = make_response(render_template('index.html'))
            response.headers['Content-Type'] = 'text/html'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Location'] = '/'
            response.set_cookie('auth',auth_token,max_age=3600,httponly=True)
            response.status_code = 302
            return response
        else:
            login_error = "Invalid username or password. Try again."
            return render_template('index.html', login_error=login_error)
    else:
        login_error = "Invalid username or password. Try again."
        return render_template('index.html', login_error=login_error)

@app.route("/logout",methods=['POST'])
def logout():
    user_type_cookie = request.cookies.get('auth')
    if user_type_cookie != None:
        try:
            conn = mysql.connector.connect(
                user = 'user',
                password = 'password',
                host = 'db',
                database = 'db'
            )
            cursor = conn.cursor()
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        query = "SELECT * FROM user"
        cursor.execute(query)
        result = cursor.fetchall()
        username =''
        for user in result:
            if(hashlib.sha256(user_type_cookie.encode('utf-8')).hexdigest() == user[3]):
                username = user[1]
                break
        #after we find out which user it is
        logout_query = "UPDATE user SET auth_token=%s WHERE username=%s"
        values = ("0",username)
        cursor.execute(logout_query,values)
        conn.commit()
        cursor.close()
        conn.close()
        response = make_response(redirect('/'))
        response.set_cookie('auth',"0",max_age=0,httponly=True)
        return response

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080,debug=False)