const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect("MONGODB_ATLAS_URL");

const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
  balance: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
  verified: { type: Boolean, default: false },
  banned: { type: Boolean, default: false }
});

const SECRET = "DV_SECRET_KEY";

/* MAIL */
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "SENDER_MAIL@gmail.com",
    pass: "GMAIL_APP_PASSWORD"
  }
});

/* REGISTER */
app.post("/register", async (req,res)=>{
  const {username,email,password} = req.body;

  if(await User.findOne({email}))
    return res.status(400).send("Mail kayıtlı");

  const hash = await bcrypt.hash(password,10);

  const user = await User.create({
    username,
    email,
    password: hash
  });

  const token = jwt.sign({id:user._id}, SECRET, {expiresIn:"1d"});
  const link = `https://FRONTEND-SITE/verify.html?token=${token}`;

  await mailer.sendMail({
    to: email,
    subject: "DV Cüzdan Mail Doğrulama",
    html: `
      <h2>DV Cüzdan</h2>
      <p>Hesabını doğrulamak için tıkla:</p>
      <a href="${link}">HESABI DOĞRULA</a>
    `
  });

  res.send("Doğrulama maili gönderildi");
});

/* VERIFY */
app.get("/verify", async (req,res)=>{
  try{
    const {id} = jwt.verify(req.query.token,SECRET);
    await User.findByIdAndUpdate(id,{verified:true});
    res.send("Hesabın doğrulandı, giriş yapabilirsin.");
  }catch{
    res.status(400).send("Geçersiz veya süresi dolmuş link");
  }
});

/* LOGIN */
app.post("/login", async (req,res)=>{
  const {email,password} = req.body;
  const user = await User.findOne({email});
  if(!user) return res.sendStatus(404);

  if(!(await bcrypt.compare(password,user.password)))
    return res.sendStatus(401);

  if(!user.verified)
    return res.status(403).send("Mail doğrulanmamış");

  if(user.banned)
    return res.status(403).send("Hesap banlı");

  const token = jwt.sign(
    {id:user._id,isAdmin:user.isAdmin},
    SECRET
  );

  res.json({token});
});

/* AUTH */
function auth(req,res,next){
  try{
    req.user = jwt.verify(req.headers.authorization,SECRET);
    next();
  }catch{
    res.sendStatus(401);
  }
}

/* ME */
app.get("/me",auth,async(req,res)=>{
  res.json(await User.findById(req.user.id));
});

/* ADMIN PARA BAS */
app.post("/admin/mint",auth,async(req,res)=>{
  if(!req.user.isAdmin) return res.sendStatus(403);
  const {username,amount} = req.body;
  const u = await User.findOne({username});
  if(!u) return res.sendStatus(404);
  u.balance += amount;
  await u.save();
  res.send("OK");
});

/* ADMIN ISTATISTIK */
app.get("/admin/stats",auth,async(req,res)=>{
  if(!req.user.isAdmin) return res.sendStatus(403);
  const users = await User.countDocuments();
  const total = await User.aggregate([{ $group:{_id:null,sum:{$sum:"$balance"}}}]);
  res.json({users,totalDV: total[0]?.sum || 0});
});

app.listen(3000,()=>console.log("DV Server aktif"));
