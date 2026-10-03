"""Execute the generated proxy certificate call with the real configured hostname mismatch."""
import pathlib,sys,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
import deploy
source=(root.parent/'MeshCentral/node_modules/meshcentral/meshcentral.js').read_text(encoding='utf-8')
fixed=deploy.align_proxy_certificate_sni(source)
assert deploy.align_proxy_certificate_sni(fixed)==fixed
assert deploy.align_proxy_certificate_sni(fixed.replace('\n','\r\n'))==fixed.replace('\n','\r\n')
call=next(line.strip() for line in fixed.splitlines() if 'obj.certificateOperations.loadCertificate(obj.config.domains[i].certurl,' in line)
statement=call.split(', function (url, cert, xhostname, xdomain)')[0]+');'
fixture="""const assert=require('assert');
let seen;
const obj={config:{domains:{'':{certurl:''}}},certificateOperations:{loadCertificate:(url,hostname,domain)=>{seen={url,hostname,domain}}}};
const i='', dnsname='high.support';
for(const [url,expected] of [['https://agents.high.support/','agents.high.support'],['https://agents.high.support:443/path','agents.high.support'],['file:/public/cert.pem','high.support']]) {
 obj.config.domains[i].certurl=url;
 STATEMENT
 assert.equal(seen.hostname,expected);
 assert.equal(seen.url,url);
 assert.equal(seen.domain,obj.config.domains[i]);
}
console.log('Proxy certificate SNI follows HTTPS URL; file loading preserves domain hostname.');
""".replace('STATEMENT',statement)
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d)/'sni.js';p.write_text(fixture)
 subprocess.run(['node',str(p)],check=True)
try: deploy.align_proxy_certificate_sni('unsupported')
except ValueError: pass
else: raise AssertionError('Unknown loader must fail closed')
