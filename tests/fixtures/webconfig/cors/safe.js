const allow=new Set(["https://app.example.com"]);
const app=require("express")();
app.use((req,res,next)=>{
  const o=req.headers.origin;
  if(allow.has(o)) res.setHeader("Access-Control-Allow-Origin", o);
  next();
});
