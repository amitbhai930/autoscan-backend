require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URL)
  .then(()=>console.log("MongoDB connected"))
  .catch(err=>console.log(err));

const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
  role: { type: String, default: "user" }
});
const User = mongoose.model("User", UserSchema);

const SECRET = process.env.JWT_SECRET;

// Signup
app.post('/api/signup', async (req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10);
  await User.create({ email:req.body.email, password:hash });
  res.json({status:"ok"});
});

// Login
app.post('/api/login', async (req,res)=>{
  const user = await User.findOne({ email:req.body.email });
  if(!user) return res.status(401).json({error:"Invalid"});
  const ok = await bcrypt.compare(req.body.password,user.password);
  if(!ok) return res.status(401).json({error:"Invalid"});
  const token = jwt.sign({id:user._id, role:user.role}, SECRET);
  res.json({token});
});

// Admin: get users
app.get('/api/admin/users', async (req,res)=>{
  const data = jwt.verify(req.headers.authorization, SECRET);
  if(data.role !== "admin") return res.sendStatus(403);
  const users = await User.find({}, {password:0});
  res.json(users);
});

app.listen(5000, ()=>console.log("Backend running on 5000"));

