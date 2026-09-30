import os, json, secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-dev-secret-before-deployment')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///podsenti nel.db').replace(' ', '')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default='medium')
    status = db.Column(db.String(30), nullable=False, default='investigating')
    namespace = db.Column(db.String(80), default='default')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(160), nullable=False)
    actor = db.Column(db.String(80), default='demo-user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

DEMO_PODS = [
    {'name':'api-gateway-7c8d9','namespace':'production','status':'Running','restarts':0,'cpu':31,'memory':48},
    {'name':'payments-worker-5f4b2','namespace':'production','status':'Running','restarts':1,'cpu':67,'memory':72},
    {'name':'catalog-api-6b9c1','namespace':'production','status':'CrashLoopBackOff','restarts':8,'cpu':14,'memory':91},
    {'name':'redis-cache-0','namespace':'data','status':'Running','restarts':0,'cpu':22,'memory':58},
    {'name':'checkout-7d2e4','namespace':'staging','status':'Pending','restarts':0,'cpu':0,'memory':0},
]

def log_action(action):
    db.session.add(AuditLog(action=action, actor=session.get('username', 'demo-user')))
    db.session.commit()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error':'Login required'}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.get('/api/health')
def health():
    return jsonify({'status':'ok','mode':'demo' if os.getenv('DEMO_MODE','true').lower() == 'true' else 'live-ready','timestamp':datetime.now(timezone.utc).isoformat()})

@app.post('/api/auth/register')
def register():
    data = request.get_json(silent=True) or {}
    username, password = data.get('username','').strip(), data.get('password','')
    if len(username) < 3 or len(password) < 8:
        return jsonify({'error':'Username must be 3+ characters and password 8+ characters.'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error':'Username already exists.'}), 409
    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user); db.session.commit()
    session['username'] = username
    log_action('Account created')
    return jsonify({'username':username,'message':'Account created'})

@app.post('/api/auth/login')
def login():
    data = request.get_json(silent=True) or {}
    user = User.query.filter_by(username=data.get('username','').strip()).first()
    if not user or not check_password_hash(user.password_hash, data.get('password','')):
        return jsonify({'error':'Invalid username or password.'}), 401
    session['username'] = user.username
    log_action('Signed in')
    return jsonify({'username':user.username,'message':'Signed in'})

@app.post('/api/auth/logout')
def logout():
    session.clear()
    return jsonify({'message':'Signed out'})

@app.get('/api/auth/me')
def me():
    return jsonify({'username':session.get('username'),'authenticated':bool(session.get('username'))})

@app.get('/api/cluster')
def cluster():
    pods = DEMO_PODS
    running = sum(p['status']=='Running' for p in pods)
    return jsonify({'name':'prod-cluster-east','provider':'Kubernetes','version':'v1.31.x','health':92,'nodes':6,'pods_total':len(pods),'pods_running':running,'cpu':43,'memory':68,'pods':pods,'source':'simulated demo data' if os.getenv('DEMO_MODE','true').lower() == 'true' else 'not configured'})

@app.get('/api/metrics')
def metrics():
    return jsonify({'labels':['-5m','-4m','-3m','-2m','-1m','Now'],'cpu':[34,38,35,44,41,43],'memory':[59,61,62,66,65,68],'restarts':[1,1,2,2,3,3],'source':'simulated demo data'})

@app.get('/api/incidents')
def incidents():
    if Incident.query.count() == 0:
        for title, sev, status, ns in [('Catalog API restart loop','high','investigating','production'),('Checkout pod pending','medium','open','staging'),('Memory pressure warning','low','resolved','data')]:
            db.session.add(Incident(title=title, severity=sev, status=status, namespace=ns))
        db.session.commit()
    rows = Incident.query.order_by(Incident.created_at.desc()).all()
    return jsonify([{'id':i.id,'title':i.title,'severity':i.severity,'status':i.status,'namespace':i.namespace,'created_at':i.created_at.isoformat()+'Z'} for i in rows])

@app.post('/api/incidents/simulate')
def simulate_incident():
    data = request.get_json(silent=True) or {}
    kind = data.get('kind','CrashLoopBackOff')
    valid = {'CrashLoopBackOff':'high','OOMKilled':'high','Unhealthy rollout':'medium','Node memory pressure':'medium'}
    if kind not in valid: return jsonify({'error':'Unknown incident type'}), 400
    incident = Incident(title=kind, severity=valid[kind], status='awaiting approval', namespace=data.get('namespace','production'))
    db.session.add(incident); db.session.commit()
    log_action(f'Simulated incident created: {kind}')
    return jsonify({'message':'Incident simulated','incident':{'id':incident.id,'title':incident.title,'severity':incident.severity,'status':incident.status}}), 201

@app.post('/api/remediation/<int:incident_id>')
def remediation(incident_id):
    data = request.get_json(silent=True) or {}
    decision = data.get('decision')
    if decision not in ('approve','reject'): return jsonify({'error':'Decision must be approve or reject'}), 400
    incident = db.session.get(Incident, incident_id)
    if not incident: return jsonify({'error':'Incident not found'}), 404
    # Safe-by-default: approval records intent only. No live cluster mutation is performed in demo mode.
    incident.status = 'approved (simulation)' if decision == 'approve' else 'rejected'
    db.session.commit(); log_action(f'{decision.title()} remediation for incident #{incident_id}')
    return jsonify({'message':f'Remediation {decision} recorded','status':incident.status,'live_action_executed':False})

@app.get('/api/audit')
def audit():
    rows = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(40).all()
    return jsonify([{'action':r.action,'actor':r.actor,'created_at':r.created_at.isoformat()+'Z'} for r in rows])

@app.get('/api/config')
def config():
    return jsonify({'backend':'Flask + SQLAlchemy','database':'PostgreSQL' if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite','kubernetes_client':'optional; configure cluster credentials','prometheus':'optional; set PROMETHEUS_URL','auth':'Flask secure session cookie','deployment':['Docker','Kubernetes manifests'],'demo_mode':os.getenv('DEMO_MODE','true').lower() == 'true'})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=os.getenv('FLASK_DEBUG','false').lower() == 'true')
