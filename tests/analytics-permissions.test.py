import pathlib,subprocess
p=pathlib.Path(__file__).with_name('analytics-permission-case.php');good=['cyberdat_staging','staging','/var/www/cyberdat-staging/public/','https://staging.cyberdat.eu/','cyberdat_staging_admin'];cases=[(good,'yes')]
for i,value in [(0,'cyberdat_wp'),(1,'production'),(2,'/var/www/cyberdat/public/'),(3,'https://cyberdat.eu/'),(4,'missing'),(4,''),(4,'array')]:
 args=good.copy();args[i]=value;cases.append((args,'no'))
for args,expected in cases:
 r=subprocess.run(['php8.4',str(p),*args,expected],capture_output=True,text=True);assert r.returncode==0,r.stderr
print('PASS: eight actual staging/database/root/home/Basic Auth permission contexts')
