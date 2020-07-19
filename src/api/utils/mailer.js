const express=require('express')
const nodemailer = require("nodemailer")
const app = express()
require('dotenv').config()

const smtpTransport = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
})

module.exports.sendVerificationEmail = async (host,email,username,token) => {
	console.log(`in sendVerificationEmail\nhost ${host},email ${email},username ${username},token ${token}`)
	let link = `http://${host}/v1/auth/verify?id=${token}`
	let mailOptions={
        to : email,
        subject : `Please confirm your Email account`,
        html : `Dear ${username},<br> Please click <a href="${link}">here</a> to verify your email.`
    }
    smtpTransport.sendMail(mailOptions, function(error, response){
		if(error){
			console.log(`Error in sending mail. Error: ${error}`)
		}else{
			console.log(`Mail sent: ${response}`)
		}
	})
}

module.exports.sendResetPassword = async (host,email,username,token) => {
	console.log(`in sendResetPassword\nhost ${host},email ${email},username ${username},token ${token}`)
	let link = `http://${host}/v1/auth/reset-password?id=${token}`
	let mailOptions={
        to : email,
        subject : `Reset Password`,
        html : `Dear ${username},<br> Please click <a href="${link}">here</a> to reset your password.`
    }
    smtpTransport.sendMail(mailOptions, function(error, response){
		if(error){
			console.log(`Error in sending mail. Error: ${error}`)
		}else{
			console.log(`Mail sent: ${response}`)
		}
	})
}