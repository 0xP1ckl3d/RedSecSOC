import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from integrity import digest,verify

STATUSES=('New','Investigating','False positive','Resolved','Closed')
ROLES=('admin','analyst','viewer')


class StateConflict(Exception):pass


def password_hash(password, salt=None):
    salt=salt or secrets.token_hex(16)
    digest=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
    return salt+':'+digest


def password_valid(password,encoded):
    return hmac.compare_digest(password_hash(password,encoded.split(':')[0]),encoded)


class Store:
    def __init__(self,path):
        self.path=path
        os.makedirs(os.path.dirname(path) or '.',exist_ok=True)
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,password TEXT NOT NULL,role TEXT NOT NULL,disabled INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user TEXT NOT NULL,csrf TEXT NOT NULL,created REAL NOT NULL,last_seen REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS states(key TEXT PRIMARY KEY,status TEXT NOT NULL,assignee TEXT NOT NULL DEFAULT '',updated REAL NOT NULL,actor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL,status TEXT NOT NULL,assignee TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,actor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,event_key TEXT NOT NULL,source_index TEXT NOT NULL,source_id TEXT NOT NULL,digest TEXT NOT NULL,snapshot TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL,UNIQUE(case_id,event_key));
            CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,subject TEXT NOT NULL,body TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY,subject TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS validations(id TEXT PRIMARY KEY,title TEXT NOT NULL,host TEXT NOT NULL,start TEXT NOT NULL,end TEXT NOT NULL,marker TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS clear_batches(id TEXT PRIMARY KEY,actor TEXT NOT NULL,created REAL NOT NULL,payload TEXT NOT NULL,undone INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS event_refs(key TEXT PRIMARY KEY,source_index TEXT NOT NULL,source_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS group_decisions(key TEXT PRIMARY KEY,classification TEXT NOT NULL,rationale TEXT NOT NULL,actor TEXT NOT NULL,updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS pattern_policies(id TEXT PRIMARY KEY,kind TEXT NOT NULL,criteria TEXT NOT NULL,classification TEXT NOT NULL,rationale TEXT NOT NULL,actor TEXT NOT NULL,updated REAL NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);
            CREATE INDEX IF NOT EXISTS evidence_case ON evidence(case_id);
            CREATE INDEX IF NOT EXISTS notes_subject ON notes(subject);
            CREATE INDEX IF NOT EXISTS history_subject ON history(subject);
            ''')
        if os.name!='nt':os.chmod(path,0o600)
        self.review_unsafe_policies()

    def review_unsafe_policies(self):
        from patterns import validate_safe
        with self.db() as db:
            for row in db.execute("SELECT * FROM pattern_policies WHERE enabled=1 AND classification='Safe'").fetchall():
                try:validate_safe(row['kind'],json.loads(row['criteria']))
                except ValueError as exc:
                    db.execute('UPDATE pattern_policies SET enabled=0 WHERE id=?',(row['id'],))
                    self.record(db,'pattern:'+row['id'],'Safe scope requires review',{'reason':str(exc),'criteria':json.loads(row['criteria'])},'scope-validation')

    @contextlib.contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=5)
        db.row_factory=sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:db.close()

    def record(self,db,subject,action,detail,actor):
        db.execute('INSERT INTO history(subject,action,detail,actor,created) VALUES(?,?,?,?,?)',(subject,action,json.dumps(detail,ensure_ascii=False),actor,time.time()))

    def initialize(self,user,password):
        with self.db() as db:
            if db.execute('SELECT COUNT(*) FROM users').fetchone()[0]:return
            db.execute('INSERT INTO users(name,password,role) VALUES(?,?,?)',(user,password_hash(password),'admin'))
            self.record(db,'system','Initial administrator created',{'user':user},'setup')

    def login(self,name,password):
        with self.db() as db:
            row=db.execute('SELECT * FROM users WHERE name=? AND disabled=0',(name,)).fetchone()
            # Same password cost for nonexistent accounts.
            encoded=row['password'] if row else password_hash('unused-placeholder',salt='0'*32)
            valid=password_valid(password,encoded)
            if not row or not valid:return None
            token=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32);now=time.time()
            db.execute('DELETE FROM sessions WHERE created<? OR last_seen<?',(now-28800,now-1800))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),name,csrf,now,now))
            self.record(db,'system','Sign in',{},name)
            return {'token':token,'csrf':csrf,'name':name,'role':row['role']}

    def session(self,token):
        if not token:return None
        key=hashlib.sha256(token.encode()).hexdigest();now=time.time()
        with self.db() as db:
            row=db.execute('SELECT s.*,u.role,u.disabled FROM sessions s JOIN users u ON s.user=u.name WHERE s.token=?',(key,)).fetchone()
            if not row or row['disabled'] or now-row['created']>28800 or now-row['last_seen']>1800:return None
            if now-row['last_seen']>60:db.execute('UPDATE sessions SET last_seen=? WHERE token=?',(now,key))
            return {'name':row['user'],'role':row['role'],'csrf':row['csrf']}

    def logout(self,token):
        with self.db() as db:db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(token.encode()).hexdigest(),))

    def states(self,keys=None):
        with self.db() as db:
            if keys is None:rows=db.execute('SELECT * FROM states').fetchall()
            elif not keys:return {}
            else:rows=db.execute('SELECT * FROM states WHERE key IN ('+','.join('?' for _ in keys)+')',keys).fetchall()
            return {r['key']:dict(r) for r in rows}

    def state(self,key,status,assignee,actor):
        if status not in STATUSES:raise ValueError('Invalid disposition')
        with self.db() as db:
            before=db.execute('SELECT status,assignee FROM states WHERE key=?',(key,)).fetchone()
            db.execute('INSERT INTO states VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET status=excluded.status,assignee=excluded.assignee,updated=excluded.updated,actor=excluded.actor',(key,status,assignee,time.time(),actor))
            self.record(db,key,'Alert disposition changed',{'before':dict(before) if before else {'status':'New','assignee':''},'after':{'status':status,'assignee':assignee}},actor)

    def annotations(self,subject):
        with self.db() as db:
            return {'notes':[dict(r) for r in db.execute('SELECT * FROM notes WHERE subject=? ORDER BY id',(subject,))], 'history':[dict(r) for r in db.execute('SELECT * FROM history WHERE subject=? ORDER BY id',(subject,))]}

    def clear_alerts(self,entries,actor):
        batch=secrets.token_hex(16);now=time.time();changes=[]
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            for entry in entries:
                row=db.execute('SELECT * FROM states WHERE key=?',(entry['key'],)).fetchone()
                before=dict(row) if row else {'status':'New','assignee':'','updated':None}
                if before['status']!=entry['expected_status'] or before.get('updated')!=entry.get('expected_updated'):
                    raise StateConflict('An alert changed since this list was loaded. Refresh and select it again; no alerts were cleared.')
                if before['status']=='Closed':continue
                changes.append({'key':entry['key'],'index':entry['index'],'eid':entry['eid'],'before':{'status':before['status'],'assignee':before['assignee']},'updated':now})
            for item in changes:
                db.execute('INSERT INTO states VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET status=excluded.status,assignee=excluded.assignee,updated=excluded.updated,actor=excluded.actor',(item['key'],'Closed',item['before']['assignee'],now,actor))
                db.execute('INSERT OR REPLACE INTO event_refs VALUES(?,?,?)',(item['key'],item['index'],item['eid']))
                self.record(db,item['key'],'Alert cleared',{'batch':batch,'before':item['before'],'after':{'status':'Closed','assignee':item['before']['assignee']}},actor)
            if changes:db.execute('INSERT INTO clear_batches VALUES(?,?,?,?,0)',(batch,actor,now,json.dumps(changes)))
            db.execute('DELETE FROM clear_batches WHERE created<?',(now-86400,))
        return {'batch_id':batch if changes else None,'count':len(changes),'undo_until':now+600 if changes else None}

    def undo_clear(self,batch,actor,admin=False):
        now=time.time()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM clear_batches WHERE id=?',(batch,)).fetchone()
            if not row or row['undone'] or now-row['created']>600:raise StateConflict('This clear action is no longer available to undo.')
            if row['actor']!=actor and not admin:raise PermissionError('Only the original analyst or an administrator can undo this action')
            changes=json.loads(row['payload'])
            for item in changes:
                current=db.execute('SELECT status,updated FROM states WHERE key=?',(item['key'],)).fetchone()
                if not current or current['status']!='Closed' or current['updated']!=item['updated']:
                    raise StateConflict('An alert has been changed since it was cleared. Undo was cancelled to preserve that change.')
            for item in changes:
                old=item['before'];db.execute('UPDATE states SET status=?,assignee=?,updated=?,actor=? WHERE key=?',(old['status'],old['assignee'],now,actor,item['key']))
                self.record(db,item['key'],'Alert clear undone',{'batch':batch,'restored':old},actor)
            db.execute('UPDATE clear_batches SET undone=1 WHERE id=?',(batch,))
        return {'count':len(changes)}

    def note(self,subject,body,actor):
        with self.db() as db:
            db.execute('INSERT INTO notes(subject,body,actor,created) VALUES(?,?,?,?)',(subject,body,actor,time.time()))
            self.record(db,subject,'Note added',{},actor)

    def cases(self):
        with self.db() as db:return [dict(r) for r in db.execute('SELECT c.*, (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) AS evidence_count FROM cases c ORDER BY updated DESC LIMIT 500')]

    def case_counts(self):
        with self.db() as db:
            rows=db.execute('SELECT status,COUNT(*) AS count FROM cases GROUP BY status').fetchall()
        counts={r['status']:r['count'] for r in rows}
        return {'open':sum(counts.get(s,0) for s in ('New','Investigating')),'by_status':counts,'scope':'All retained analyst-created investigations; not limited to the telemetry time window'}

    def case(self,cid):
        with self.db() as db:
            c=db.execute('SELECT * FROM cases WHERE id=?',(cid,)).fetchone()
            if not c:return None
            result=dict(c)
            result['evidence']=[dict(r) for r in db.execute('SELECT * FROM evidence WHERE case_id=? ORDER BY created',(cid,))]
        for row in result['evidence']:
            row['snapshot']=json.loads(row['snapshot']);row['integrity']=verify(row['snapshot'],row['digest'])
        return result|self.annotations(cid)

    def save_case(self,cid,title,description,status,assignee,actor):
        if status not in STATUSES:raise ValueError('Invalid disposition')
        cid=cid or 'case-'+secrets.token_hex(8);now=time.time()
        with self.db() as db:
            old=db.execute('SELECT * FROM cases WHERE id=?',(cid,)).fetchone()
            db.execute('INSERT INTO cases VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,description=excluded.description,status=excluded.status,assignee=excluded.assignee,updated=excluded.updated,actor=excluded.actor',(cid,title,description,status,assignee,now,now,actor))
            self.record(db,cid,'Case updated' if old else 'Case created',{'title':title,'status':status,'assignee':assignee},actor)
        return cid

    def pin(self,cid,event,source,actor,analysis=None):
        canonical=json.dumps(source,sort_keys=True,ensure_ascii=False,separators=(',',':'))
        if len(canonical.encode())>2000000:raise ValueError('Source record exceeds the 2 MB evidence limit')
        snapshot={'event':event,'source':source,'analysis':analysis or {}}
        with self.db() as db:
            if not db.execute('SELECT id FROM cases WHERE id=?',(cid,)).fetchone():raise ValueError('Case not found')
            old=db.execute('SELECT digest FROM evidence WHERE case_id=? AND event_key=?',(cid,event['key'])).fetchone()
            if old and old['digest']!=digest(source):raise StateConflict('This event identity already has a different preserved source digest. The existing evidence was retained; investigate the source change.')
            if old:return
            if db.execute('SELECT count(*) FROM evidence WHERE case_id=?',(cid,)).fetchone()[0]>=200:raise ValueError('Case evidence limit reached (200 records)')
            cur=db.execute('INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?,?,?)',(secrets.token_hex(16),cid,event['key'],event['ref']['index'],event['ref']['id'],hashlib.sha256(canonical.encode()).hexdigest(),json.dumps(snapshot,ensure_ascii=False),time.time(),actor))
            if cur.rowcount:
                self.record(db,cid,'Evidence pinned',{'event_key':event['key'],'source':event['ref'],'sha256':hashlib.sha256(canonical.encode()).hexdigest()},actor)
                db.execute('UPDATE cases SET updated=? WHERE id=?',(time.time(),cid))

    def group_decisions(self):
        with self.db() as db:return {r['key']:dict(r) for r in db.execute('SELECT * FROM group_decisions')}

    def validate_sequence(self,entries,analysis):
        if not 1<=len(entries)<=60:raise ValueError('Select a narrower sequence (maximum 60 evidence records per batch)')
        analysis_size=len(json.dumps(analysis,ensure_ascii=False).encode())
        if analysis_size>2000000:raise ValueError('Relationship evidence exceeds 2 MB; narrow the context window')
        prepared=[]
        batch_size=analysis_size
        for event,source in entries:
            canonical=json.dumps(source,sort_keys=True,ensure_ascii=False,separators=(',',':'))
            if len(canonical.encode())>2000000:raise ValueError('Source record exceeds the 2 MB evidence limit')
            batch_size+=len(canonical.encode())
            prepared.append((event,source,hashlib.sha256(canonical.encode()).hexdigest()))
        if batch_size>8000000:raise ValueError('Sequence evidence exceeds 8 MB; narrow the context window')
        return prepared

    def pin_sequence(self,cid,entries,analysis,actor):
        """Validate and preserve a linked component as one atomic evidence batch."""
        prepared=self.validate_sequence(entries,analysis)
        now=time.time()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT id FROM cases WHERE id=?',(cid,)).fetchone():raise ValueError('Case not found')
            old={r['event_key']:r['digest'] for r in db.execute('SELECT event_key,digest FROM evidence WHERE case_id=?',(cid,))}
            if len(set(old)|{e['key'] for e,s,d in prepared})>200:raise ValueError('Case evidence limit reached (200 records)')
            for event,source,checksum in prepared:
                if event['key'] in old and old[event['key']]!=checksum:raise StateConflict('A preserved source changed; the entire new sequence batch was cancelled')
            added=0
            for event,source,checksum in prepared:
                if event['key'] in old:continue
                # Preserve the full graph once, with a link from other copies;
                # history below also retains the batch graph independently.
                entry_analysis=analysis if added==0 else {k:v for k,v in analysis.items() if k!='correlation'}|{'correlation':{'id':analysis['correlation']['id'],'relationship_history':'Correlated evidence batch preserved'}}
                snapshot={'event':event,'source':source,'analysis':entry_analysis}
                db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)',(secrets.token_hex(16),cid,event['key'],event['ref']['index'],event['ref']['id'],checksum,json.dumps(snapshot,ensure_ascii=False),now,actor));added+=1
                self.record(db,cid,'Evidence pinned',{'event_key':event['key'],'source':event['ref'],'sha256':checksum,'sequence':analysis['correlation']['id']},actor)
            self.record(db,cid,'Correlated evidence batch preserved',{'sequence':analysis['correlation']['id'],'added':added,'relationships':analysis['correlation']['edges']},actor)
            db.execute('UPDATE cases SET updated=? WHERE id=?',(now,cid))
        return added

    def pattern_policies(self,include_disabled=False):
        with self.db() as db:rows=[dict(r) for r in db.execute('SELECT * FROM pattern_policies'+('' if include_disabled else ' WHERE enabled=1')+' ORDER BY updated DESC')]
        for row in rows:row['criteria']=json.loads(row['criteria'])
        return rows

    def save_pattern_policy(self,kind,criteria,classification,rationale,actor):
        from patterns import validate_criteria,validate_safe,policy_key
        criteria=validate_criteria(kind,criteria)
        if classification not in ('Safe','Suspicious'):raise ValueError('Choose Safe or Suspicious')
        if classification=='Safe':criteria=validate_safe(kind,criteria)
        if not 10<=len(rationale.strip())<=2000:raise ValueError('Record a rationale between 10 and 2000 characters')
        key=policy_key(kind,criteria);now=time.time()
        with self.db() as db:
            old=db.execute('SELECT * FROM pattern_policies WHERE id=?',(key,)).fetchone()
            if (not old or not old['enabled']) and db.execute('SELECT COUNT(*) FROM pattern_policies WHERE enabled=1').fetchone()[0]>=100:raise ValueError('Review or disable an existing pattern policy before adding more than 100 active scopes')
            db.execute('INSERT INTO pattern_policies VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET classification=excluded.classification,rationale=excluded.rationale,actor=excluded.actor,updated=excluded.updated,enabled=1',(key,kind,json.dumps(criteria,sort_keys=True),classification,rationale,actor,now))
            self.record(db,'pattern:'+key,'Pattern policy saved',{'kind':kind,'criteria':criteria,'classification':classification,'rationale':rationale,'previous_classification':old['classification'] if old else None},actor)
        return key

    def disable_pattern_policy(self,key,actor):
        with self.db() as db:
            old=db.execute('SELECT * FROM pattern_policies WHERE id=? AND enabled=1',(key,)).fetchone()
            if not old:raise ValueError('Active pattern policy not found')
            db.execute('UPDATE pattern_policies SET enabled=0,actor=?,updated=? WHERE id=?',(actor,time.time(),key))
            self.record(db,'pattern:'+key,'Pattern policy disabled',{'kind':old['kind'],'criteria':json.loads(old['criteria']),'classification':old['classification']},actor)

    def classify_group(self,key,classification,rationale,actor):
        if classification not in ('Expected recurrence','Needs investigation','Unreviewed'):raise ValueError('Invalid group classification')
        if len(rationale.strip())<10:raise ValueError('Record at least ten characters explaining this assessment')
        with self.db() as db:
            if classification=='Unreviewed':db.execute('DELETE FROM group_decisions WHERE key=?',(key,))
            else:db.execute('INSERT OR REPLACE INTO group_decisions VALUES(?,?,?,?,?)',(key,classification,rationale,actor,time.time()))
            self.record(db,'group:'+key,'Recurring pattern assessed',{'classification':classification,'rationale':rationale},actor)

    def users(self):
        with self.db() as db:return [dict(r) for r in db.execute('SELECT name,role,disabled FROM users ORDER BY name')]

    def save_user(self,name,password,role,disabled,actor):
        if role not in ROLES:raise ValueError('Invalid role')
        with self.db() as db:
            old=db.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
            if old and old['role']=='admin' and (role!='admin' or disabled):
                if db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0]<=1:raise ValueError('Keep at least one active administrator')
            if not old and not password:raise ValueError('A password is required for a new account')
            encoded=password_hash(password) if password else old['password']
            db.execute('INSERT INTO users VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET password=excluded.password,role=excluded.role,disabled=excluded.disabled',(name,encoded,role,int(disabled)))
            db.execute('DELETE FROM sessions WHERE user=?',(name,))
            self.record(db,'system','User updated',{'user':name,'role':role,'disabled':disabled},actor)
