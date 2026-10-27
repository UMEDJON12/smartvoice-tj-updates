#!/usr/bin/env python3
"""Mirror an owner-published, SDK-verified ordinary release to Drive, then expose it.

Uses owner OAuth with drive.file scope. No billing, release publication or account-wide cleanup.
Credentials belong only in GitHub Actions secrets; never in APK/JSON/logs.
"""
import base64,datetime,glob,hashlib,json,os,re,subprocess,tempfile,time,urllib.error,urllib.parse,urllib.request
from html.parser import HTMLParser
from pathlib import Path

REPO='UMEDJON12/smartvoice-tj-updates'
PACKAGE='tts.smartvoice.umedjon'
CERT='5d1d676dfddad74da47b5486b4dbe9bf66b68e67c7c256d144ec0bdf3f0ed95b'
MARKER='smartvoice-standard-v1'
KEEP=3
GRACE=datetime.timedelta(days=7)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self,provider):super().__init__();self.provider=provider
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        u=urllib.parse.urlsplit(newurl)
        allowed={'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','github-releases.githubusercontent.com'} if self.provider=='github' else {'drive.google.com','drive.usercontent.google.com'}
        if u.scheme!='https' or u.hostname not in allowed or u.username or u.password or u.port not in (None,443) or u.fragment:
            raise RuntimeError('Unapproved public download redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def canonical_drive_url(file_id):
    if not isinstance(file_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{10,200}',file_id):raise ValueError('Invalid Drive file ID')
    return 'https://drive.google.com/uc?export=download&id='+file_id

class Confirmation(HTMLParser):
    def __init__(self):super().__init__(convert_charrefs=True);self.forms=[];self.current=None;self.block=0
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style'):self.block+=1
        if self.block:return
        keys=[k for k,v in attrs]
        if len(keys)!=len(set(keys)):raise RuntimeError('Duplicate HTML attribute')
        a=dict(attrs)
        if tag=='form':
            if self.current is not None:raise RuntimeError('Nested confirmation form')
            self.current={'action':a.get('action'),'method':a.get('method','get').lower(),'fields':[]}
        elif tag=='input' and self.current is not None and a.get('name'):
            self.current['fields'].append((a.get('type','').lower(),a['name'],a.get('value','')))
    def handle_endtag(self,tag):
        if tag in ('script','style') and self.block:self.block-=1;return
        if self.block:return
        if tag=='form' and self.current is not None:self.forms.append(self.current);self.current=None

def confirmation_url(body,file_id):
    if len(body)>131072:raise RuntimeError('Drive confirmation exceeds size limit')
    p=Confirmation();p.feed(body.decode('utf-8','strict'));found=[]
    if len(p.forms)>8:raise RuntimeError('Too many confirmation forms')
    for f in p.forms:
        if f['action']!='https://drive.usercontent.google.com/download':continue
        if f['method']!='get' or len(f['fields'])>12:raise RuntimeError('Unexpected confirmation method')
        q={}
        for kind,k,v in f['fields']:
            if kind!='hidden' or k not in ('id','export','confirm','uuid','resourcekey') or k in q or len(v)>2048 or '\r' in v or '\n' in v:
                raise RuntimeError('Unexpected confirmation fields')
            q[k]=v
        if q.get('id')!=file_id or q.get('export')!='download' or q.get('confirm')!='t':raise RuntimeError('Confirmation file mismatch')
        found.append(f['action']+'?'+urllib.parse.urlencode(q))
    if len(found)!=1:raise RuntimeError('Drive public download unavailable or access restricted')
    return found[0]

def public_download(url,expected_size,expected_sha256,provider,target=None):
    opener=urllib.request.build_opener(PublicRedirect(provider));current=url
    file_id=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get('id',[None])[0]
    if provider=='drive' and canonical_drive_url(file_id)!=url:raise ValueError('Noncanonical public Drive URL')
    for attempt in range(2):
        req=urllib.request.Request(current,headers={'User-Agent':'SmartVoice-published-release-verifier','Accept-Encoding':'identity','Cache-Control':'no-cache'})
        with opener.open(req,timeout=90) as response:
            if response.status!=200:raise RuntimeError('Public APK is not ready')
            if 'text/html' in response.headers.get('Content-Type','').lower():
                if provider!='drive' or attempt:raise RuntimeError('Unexpected HTML instead of APK')
                current=confirmation_url(response.read(131073),file_id);continue
            digest=hashlib.sha256();size=0;out=target.open('wb') if target else None
            try:
                while True:
                    block=response.read(1024*1024)
                    if not block:break
                    size+=len(block)
                    if size>expected_size:raise RuntimeError('Public APK exceeds expected size')
                    digest.update(block)
                    if out:out.write(block)
            finally:
                if out:out.close()
            if size!=expected_size or digest.hexdigest()!=expected_sha256:raise RuntimeError('Public file size/SHA256 mismatch')
            return
    raise RuntimeError('Drive confirmation did not yield a file')

def json_request(url,method='GET',data=None,token=None,headers=None):
    h={'Accept':'application/json','Cache-Control':'no-cache'}
    if token:h['Authorization']='Bearer '+token
    if data is not None:h['Content-Type']='application/json'
    if headers:h.update(headers)
    req=urllib.request.Request(url,method=method,data=json.dumps(data).encode() if data is not None else None,headers=h)
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=90) as response:
        body=response.read(1048577)
        if len(body)>1048576:raise RuntimeError('API response exceeds limit')
        return json.loads(body) if body else None

def owner_access_token():
    values={k:os.environ.get(k,'') for k in ('GDRIVE_CLIENT_ID','GDRIVE_CLIENT_SECRET','GDRIVE_REFRESH_TOKEN')}
    if not all(values.values()):raise RuntimeError('Drive publishing is not connected: configure the three owner OAuth secrets first; existing channels are unchanged')
    raw=urllib.parse.urlencode({'client_id':values['GDRIVE_CLIENT_ID'],'client_secret':values['GDRIVE_CLIENT_SECRET'],'refresh_token':values['GDRIVE_REFRESH_TOKEN'],'grant_type':'refresh_token'}).encode()
    req=urllib.request.Request('https://oauth2.googleapis.com/token',data=raw,headers={'Content-Type':'application/x-www-form-urlencoded'})
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=60) as r:result=json.load(r)
    if not result.get('access_token'):raise RuntimeError('Owner OAuth renewal failed')
    return result['access_token']

def iso(value):return datetime.datetime.fromisoformat(value.replace('Z','+00:00'))

def cleanup_candidates(files,folder_id,current_id,now):
    valid=[]
    for f in files:
        a=f.get('appProperties',{})
        if a.get('svPublisher')!=MARKER or a.get('svPackage')!=PACKAGE or a.get('svReady')!='true' or folder_id not in f.get('parents',[]):continue
        if f.get('mimeType')!='application/vnd.android.package-archive' or not re.fullmatch(r'SmartVoice[-A-Za-z0-9_.]+\.apk',f.get('name','')):continue
        try:
            code=int(a['svCode']);when=iso(a['svPublishedAt'])
            if code<=0 or not re.fullmatch(r'[a-f0-9]{64}',a.get('svSha256','')) or when.tzinfo is None:continue
        except (ValueError,KeyError,TypeError):continue
        valid.append((code,when,f))
    versions=sorted({code for code,when,f in valid},reverse=True);keep=set(versions[:KEEP])
    return [f for code,when,f in valid if f.get('id')!=current_id and code not in keep and now-when>GRACE]

class Drive:
    def __init__(self,token):self.token=token;self.api='https://www.googleapis.com/drive/v3'
    def call(self,path,method='GET',data=None):return json_request(self.api+path,method,data,self.token)
    def listing(self,q):
        out=[];page=None
        for _ in range(100):
            params={'q':q,'fields':'nextPageToken,files(id,name,mimeType,size,md5Checksum,sha256Checksum,parents,appProperties)','pageSize':100}
            if page:params['pageToken']=page
            result=self.call('/files?'+urllib.parse.urlencode(params));out.extend(result.get('files',[]));page=result.get('nextPageToken')
            if not page:return out
        raise RuntimeError('Drive file listing exceeds bounded pagination')
    def folder(self):
        q="trashed=false and mimeType='application/vnd.google-apps.folder' and appProperties has { key='svPublisher' and value='"+MARKER+"' }"
        matches=self.listing(q)
        if len(matches)>1:raise RuntimeError('Multiple publisher folders: choose the existing folder before continuing')
        if matches:return matches[0]['id']
        return self.call('/files?fields=id','POST',{'name':'SmartVoice Published Updates','mimeType':'application/vnd.google-apps.folder','appProperties':{'svPublisher':MARKER}})['id']
    def upload(self,apk,folder,metadata,published_at):
        q="trashed=false and '"+folder+"' in parents and appProperties has { key='svPublisher' and value='"+MARKER+"' }"
        files=self.listing(q)
        same=[f for f in files if f.get('appProperties',{}).get('svSha256')==metadata['sha256'] and f.get('appProperties',{}).get('svCode')==str(metadata['versionCode']) and int(f.get('size',0))==metadata['sizeBytes']]
        if len(same)>1:raise RuntimeError('Ambiguous matching managed uploads')
        if same:return same[0]['id']
        a={'svPublisher':MARKER,'svPackage':PACKAGE,'svCode':str(metadata['versionCode']),'svSha256':metadata['sha256'],'svPublishedAt':published_at,'svReady':'false'}
        payload={'name':metadata['apkFileName'],'mimeType':'application/vnd.android.package-archive','parents':[folder],'appProperties':a}
        req=urllib.request.Request('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,size,md5Checksum,sha256Checksum',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json; charset=UTF-8','X-Upload-Content-Type':'application/vnd.android.package-archive','X-Upload-Content-Length':str(metadata['sizeBytes'])})
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=90) as r:session=r.headers.get('Location')
        parsed=urllib.parse.urlsplit(session or '')
        if parsed.scheme!='https' or parsed.hostname!='www.googleapis.com' or parsed.username or parsed.port not in (None,443) or not parsed.path.startswith('/upload/drive/v3/files'):raise RuntimeError('Unapproved upload session')
        # Exactly one in-flight chunk; progress is queried after a transient failure.
        total=metadata['sizeBytes'];offset=0;result=None;failures=0;opener=urllib.request.build_opener(NoRedirect())
        with apk.open('rb') as source:
            while offset<total:
                source.seek(offset);chunk=source.read(min(8*1024*1024,total-offset));end=offset+len(chunk)-1
                req=urllib.request.Request(session,data=chunk,method='PUT',headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/vnd.android.package-archive','Content-Range':f'bytes {offset}-{end}/{total}'})
                try:
                    with opener.open(req,timeout=150) as r:result=json.load(r)
                    offset=total;break
                except urllib.error.HTTPError as e:
                    if e.code==308:
                        match=re.fullmatch(r'bytes=0-([0-9]+)',e.headers.get('Range',''))
                        if not match:raise RuntimeError('Upload progress missing')
                        acknowledged=int(match.group(1))+1
                        if acknowledged<=offset or acknowledged>end+1:raise RuntimeError('Unexpected upload range')
                        offset=acknowledged;failures=0;continue
                    if e.code not in (408,429,500,502,503,504):raise
                except (TimeoutError,urllib.error.URLError):pass
                failures+=1
                if failures>3:raise RuntimeError('Drive upload retry limit reached')
                time.sleep(min(failures,3))
                status=urllib.request.Request(session,data=b'',method='PUT',headers={'Authorization':'Bearer '+self.token,'Content-Range':f'bytes */{total}'})
                try:
                    with opener.open(status,timeout=90) as r:result=json.load(r)
                    offset=total
                except urllib.error.HTTPError as e:
                    if e.code!=308:raise
                    match=re.fullmatch(r'bytes=0-([0-9]+)',e.headers.get('Range',''))
                    acknowledged=int(match.group(1))+1 if match else 0
                    if acknowledged<0 or acknowledged>total:raise RuntimeError('Unexpected resumed upload range')
                    offset=acknowledged
        if not result or int(result.get('size',0))!=total:raise RuntimeError('Incomplete Drive upload')
        local_md5=hashlib.md5(apk.read_bytes()).hexdigest()
        if result.get('md5Checksum')!=local_md5:raise RuntimeError('Uploaded file checksum mismatch')
        if result.get('sha256Checksum') and result['sha256Checksum']!=metadata['sha256']:raise RuntimeError('Uploaded SHA256 mismatch')
        return result['id']
    def make_public(self,file_id):
        permissions=self.call('/files/'+file_id+'/permissions?fields=permissions(id,type,role,allowFileDiscovery)').get('permissions',[])
        if any(p.get('type')=='anyone' and p.get('role')=='reader' and p.get('allowFileDiscovery') is False for p in permissions):return
        if any(p.get('type')=='anyone' and p.get('role')!='reader' for p in permissions):raise RuntimeError('Managed file has unexpected public write access')
        self.call('/files/'+file_id+'/permissions?fields=id','POST',{'type':'anyone','role':'reader','allowFileDiscovery':False})
    def ready(self,file_id):
        data=self.call('/files/'+file_id+'?fields=appProperties');a=data['appProperties'];a['svReady']='true'
        self.call('/files/'+file_id+'?fields=id','PATCH',{'appProperties':a})
    def cleanup(self,folder,current):
        q="trashed=false and '"+folder+"' in parents and appProperties has { key='svPublisher' and value='"+MARKER+"' }"
        victims=cleanup_candidates(self.listing(q),folder,current,datetime.datetime.now(datetime.timezone.utc))
        for f in victims:self.call('/files/'+f['id'],'DELETE')
        return len(victims)

def verify_apk(apk,data):
    def sdk(name):
        roots=[os.environ.get('ANDROID_HOME','/usr/local/lib/android/sdk'),os.environ.get('ANDROID_SDK_ROOT','')]
        matches=sorted([p for root in roots if root for p in glob.glob(root+'/build-tools/*/'+name)],reverse=True)
        if not matches:raise RuntimeError('Android SDK verifier missing: '+name)
        return matches[0]
    signature=subprocess.check_output([sdk('apksigner'),'verify','--print-certs',str(apk)],text=True)
    if re.findall(r'certificate SHA-256 digest: ([a-fA-F0-9]+)',signature)!=[CERT]:raise RuntimeError('Wrong Android signing certificate')
    badging=subprocess.check_output([sdk('aapt'),'dump','badging',str(apk)],text=True)
    m=re.search(r"package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'",badging)
    if not m or (m.group(1),int(m.group(2)),m.group(3))!=(PACKAGE,data['versionCode'],data['versionName']):raise RuntimeError('Wrong package/version')
    if int(re.search(r"sdkVersion:'([0-9]+)'",badging).group(1))!=data['minSdk']:raise RuntimeError('Wrong minimum SDK')

def main():
    if os.environ.get('GITHUB_REPOSITORY')!=REPO:raise RuntimeError('Wrong repository')
    # Fail before file changes when setup is incomplete.
    drive=Drive(owner_access_token());gh=os.environ['GH_TOKEN'];api='https://api.github.com/repos/'+REPO
    def github(path,method='GET',data=None):return json_request(api+path,method,data,gh)
    release=github('/releases/latest')
    if os.environ.get('GITHUB_EVENT_NAME')=='release':
        target=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())['release']
        if target['draft'] or target['prerelease']:return
        for attempt in range(10):
            if release['id']==target['id']:break
            time.sleep(3);release=github('/releases/latest')
        if release['id']!=target['id']:raise RuntimeError('Release is not latest; Drive channel retained')
    if release['draft'] or release['prerelease'] or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+-TJ',release['tag_name']):raise RuntimeError('Not a published stable release')
    assets={a['name']:a for a in release['assets']};asset=assets['update.json']
    if asset['size']>65536:raise RuntimeError('Oversized metadata')
    with tempfile.TemporaryDirectory(prefix='sv-drive-publisher-') as td:
        root=Path(td);meta=root/'update.json';apk=root/'release.apk'
        public_download(asset['browser_download_url'],asset['size'],asset['digest'].removeprefix('sha256:'),'github',meta)
        data=json.loads(meta.read_text())
        if data['schemaVersion']!=1 or data.get('testOnly') is not False or data['variant']!='standard' or data['packageName']!=PACKAGE or data['signingCertificateSha256']!=CERT or release['tag_name']!='v'+data['versionName']:raise RuntimeError('Unapproved release metadata')
        if not isinstance(data['versionCode'],int) or isinstance(data['versionCode'],bool) or data['versionCode']<4150:raise RuntimeError('Only Drive-capable 5.2.34+ releases are mirrored')
        filename=data['apkFileName']
        if not re.fullmatch(r'SmartVoice[-A-Za-z0-9_.]+\.apk',filename):raise RuntimeError('Unexpected APK name')
        item=assets[filename];expected='https://github.com/'+REPO+'/releases/download/'+release['tag_name']+'/'+filename
        if data['apkUrl']!=expected or data['sizeBytes']!=item['size'] or not 0<data['sizeBytes']<2147483648 or item['digest']!='sha256:'+data['sha256'] or not re.fullmatch(r'[a-f0-9]{64}',data['sha256']):raise RuntimeError('APK asset/metadata mismatch')
        public_download(expected,data['sizeBytes'],data['sha256'],'github',apk);verify_apk(apk,data)
        folder=drive.folder();file_id=drive.upload(apk,folder,data,release['published_at']);drive.make_public(file_id)
        url=canonical_drive_url(file_id);public_download(url,data['sizeBytes'],data['sha256'],'drive');drive.ready(file_id)
    if github('/releases/latest')['id']!=release['id']:raise RuntimeError('Latest changed during verification; channel retained')
    channel=dict(data,downloadProvider='google-drive',driveFileId=file_id,apkUrl=url,ready=True,tagName=release['tag_name'],publishedAt=release['published_at'])
    path='/contents/updates/drive.json';body={'message':'Publish verified Google Drive download for SmartVoice '+data['versionName'],'branch':'main','content':base64.b64encode((json.dumps(channel,ensure_ascii=False,indent=2)+'\n').encode()).decode()}
    try:
        previous=github(path+'?ref=main');old=json.loads(base64.b64decode(previous['content']))
        if old['versionCode']>channel['versionCode']:raise RuntimeError('Refusing to lower Drive channel')
        body['sha']=previous['sha']
    except urllib.error.HTTPError as e:
        if e.code!=404:raise
    github(path,'PUT',body)
    deleted=0;cleanup_status='ok'
    try:deleted=drive.cleanup(folder,file_id)
    except Exception:cleanup_status='failed; existing files retained or partially cleaned; inspect managed folder'
    result={'ready':True,'versionName':data['versionName'],'versionCode':data['versionCode'],'driveFileId':file_id,'publicDownloadVerified':True,'deletedManagedOldApks':deleted,'cleanup':cleanup_status}
    print(json.dumps(result))
    with open(os.environ.get('GITHUB_STEP_SUMMARY',os.devnull),'a') as out:
        out.write('Google Drive APK verified and channel published: '+data['versionName']+'\n')
        out.write('Retained three newest versions and files younger than seven days. Cleanup: '+cleanup_status+'\n')

if __name__=='__main__':
    try:main()
    except urllib.error.HTTPError as e:raise SystemExit('API/download request failed with HTTP '+str(e.code)+'; existing channel is retained unless publication already completed')
