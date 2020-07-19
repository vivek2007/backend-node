const mongoose = require('mongoose')
const { v4: uuidv4 } = require('uuid')

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    match: /^\S+@\S+\.\S+$/,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  token : {
  	type: String,
  	default:""
  },
  uuid : {
  	type: String,
  	default:uuidv4()
  },
  password: {
    type: String,
    minlength: 6
  },
  username: {
    type: String,
    minlength: 3,
    required: true,
    unique: true,
    index: true
  },
  emailVerified:{
    type: Boolean,
    default: false
  },
  isDeleted:{
    type: Boolean,
    default: false
  },
  updatedAt:{
    type: Date,
    default: new Date()
  },
  createdAt:{
    type: Date,
    default: new Date()
  }
}, {
  timestamps: false,
}, {
  usePushEach: true,
})

module.exports = mongoose.model('User', userSchema);
