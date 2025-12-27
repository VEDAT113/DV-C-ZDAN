require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("MongoDB bağlandı"));

const User = mongoose.model("User",{
 username:String,
 email:String,
 password:String,
 balance:{type:Number,default:0},
 isAdmin:{type:Boolean,default:false}
});

/* REGISTER */
app.post("/register", async(req,res)=>{
 const {username,email,password} = req.body;

 if(await User.findOne({email}))
  return res.status(400).send("Mail zaten kayıtlı");

 const hash = await bcrypt.hash(password,10);
 await User.create({
  username,
  email,
  password:hash,
  balance:0,
  isAdmin:false
 });

 res.send("Kayıt başarılı");
});

/* LOGIN */
app.post("/login", async(req,res)=>{
 const {email,password}=req.body;
 const user=await User.findOne({email});
 if(!user) return res.status(404).send("Kullanıcı yok");

 if(!await bcrypt.compare(password,user.password))
  return res.status(401).send("Şifre yanlış");

 const token=jwt.sign(
  {id:user._id,isAdmin:user.isAdmin},
  process.env.JWT_SECRET
 );

 res.json({token});
});

/* AUTH MIDDLEWARE */
function auth(req,res,next){
 try{
  req.user=jwt.verify(req.headers.authorization,process.env.JWT_SECRET);
  next();
 }catch{
  res.sendStatus(401);
 }
}

/* WALLET */
app.get("/me",auth,async(req,res)=>{
 const u=await User.findById(req.user.id);
 res.json(u);
});

/* ADMIN PARA BAS */
app.post("/admin/mint",auth,async(req,res)=>{
 if(!req.user.isAdmin) return res.sendStatus(403);
 const {email,amount}=req.body;
 const u=await User.findOne({email});
 if(!u) return res.sendStatus(404);
 u.balance+=amount;
 await u.save();
 res.send("Para basıldı");
});

app.listen(3000,()=>console.log("DV Backend aktif"));
