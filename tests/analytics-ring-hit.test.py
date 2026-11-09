"""Execute the real CDP click expression against transformed SVG fixtures, not a browser/site."""
import ast,json,pathlib,shutil,subprocess,sys
r=pathlib.Path(__file__).resolve().parents[1];tree=ast.parse((r/'deploy/analytics-2.1/capture-analytics.py').read_text());tap=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='tap');expression=next(n.value for n in ast.walk(tap) if isinstance(n,ast.Constant) and isinstance(n.value,str) and 'new DOMPoint' in n.value)
node=shutil.which('node') or next((str(p) for p in pathlib.Path('/home/cyberdat/.vscode-server/cli/servers').glob('*/server/node') if p.is_file()),None);assert node,'Node required for actual JS-expression test'
code='''const assert=require('node:assert/strict');
const expression=EXPRESSION.replace('SELECTOR',JSON.stringify('fixture'));
let offset=0,span=0;const matrix={a:0,b:-1.4,c:1.1,d:0,e:43,f:400};
const mark={classList:{contains:c=>c==='td-ring-segment'},closest:()=>null,scrollIntoView:()=>{},getAttribute:k=>k==='stroke-dasharray'?`${span} ${100-span}`:String(-offset),getScreenCTM:()=>matrix};
global.document={querySelector:()=>mark};global.DOMPoint=class {constructor(x,y){this.x=x;this.y=y;}matrixTransform(m){return {x:m.a*this.x+m.c*this.y+m.e,y:m.b*this.x+m.d*this.y+m.f};}};
let checked=0;for(const values of [[8,32,37,5,1,17],[155,572,640,89,1,304],[361,1411]]){
 const total=values.reduce((a,b)=>a+b,0);offset=0;
 for(const value of values){span=100*value/total;const point=eval(expression),det=matrix.a*matrix.d-matrix.b*matrix.c,px=point.x-matrix.e,py=point.y-matrix.f,x=(matrix.d*px-matrix.c*py)/det,y=(-matrix.b*px+matrix.a*py)/det;
 const observed=(Math.atan2(y-110,x-110)*180/Math.PI+360)%360/3.6;
 assert(observed>=offset-1e-6&&observed<=offset+span+1e-6,'Click falls in another ring segment');assert(Math.abs(Math.hypot(x-110,y-110)-80)<1e-6);offset+=span;checked++;
 }}console.log('PASS: '+checked+' exact ring hit points, tiny None segment, existing -90 SVG rotation and nonuniform screen scaling');
'''.replace('EXPRESSION',json.dumps(expression))
result=subprocess.run([node,'-e',code],capture_output=True,text=True);assert result.returncode==0,result.stderr;print(result.stdout,end='')
# Prove this regression test detects the reported old double-rotation bug.
old=code.replace('angle=(3.6*(offset+span/2))','angle=(-90+3.6*(offset+span/2))');assert old!=code
failed=subprocess.run([node,'-e',old],capture_output=True,text=True);assert failed.returncode!=0,'Old bug unexpectedly passed'
print('PASS: old double-rotation implementation fails the same strict hit-target assertions')
