
const mongoose = require('mongoose');

const postSchema = mongoose.Schema({
    caption:{
        type:String,
        trim:true,
        required:true
    },
    description:{
        type:String,
        trim:true,

    },
    userId:{
        type: mongoose.Schema.Types.ObjectId,
        ref:'user',
        required:true

    }
},{
    timestamps:true
});

module.exports = mongoose.model('post',postSchema);