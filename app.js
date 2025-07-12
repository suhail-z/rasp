const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const authRouter = require('./routes/authRouter')
const app = express();

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({extended:true}));
app.use('/api/user',authRouter);

mongoose.connect(process.env.MONGODB_URL)
.then(()=>{
    console.log('database is connected successfully');
})
.catch((err)=>{
    console.log('error connecting with the database',err);
});

app.listen(process.env.PORT,()=>{
    console.log(`server running on port ${process.env.PORT}`);
});