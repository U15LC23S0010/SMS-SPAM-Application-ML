from app import app, get_db

app.testing = True
client = app.test_client()

with client.session_transaction() as sess:
    sess['logged_in'] = True
    sess['email'] = 'test@example.com'  # Needs a real email in DB for user_id lookup

with app.app_context():
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO users (email, name, password) VALUES ('test@example.com', 'T', 'pw')")
    conn.commit()

resp = client.post('/api/scan', data={'type': 'email', 'message': 'test email text'})
print("STATUS:", resp.status_code)
print("DATA:", resp.data.decode('utf-8'))
