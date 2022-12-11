import bcrypt from "bcrypt";
import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import randomstring from "randomstring";
import nodemailer, { createTransport } from "nodemailer";
import cors from "cors";
import * as dotenv from 'dotenv';
dotenv.config()

const app = express();

const PORT = process.env.PORT;

// connection to mongodb
const MONGO_URL= process.env.MONGO_URL

async function createConnection(){
    const client=new MongoClient(MONGO_URL);
    await client.connect();
    console.log("Mongo is connected ")
    return client;
}

export const client=await createConnection();

// home page
app.get("/", function (request, response) {
  response.send("Welcome🙋‍♂️ to the password reset page");
});

// inbuilt middleware to convert data in the body to json format
app.use(express.json())

// to connect with react
app.use(cors())

// function to generate hashed password
async function generateHashedPassword(password){
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password,salt);
  return hashedPassword;
}

// sign up 
app.post("/signUp", async function(request, response){
    const {userName, email,password} = request.body; 
    // console.log(userName, email, password);
    //find out whether the user already exists in the database
    const userFromDB = await client.db("node").collection("users").findOne({ "userName" : userName })

    // if exists send username already exists else add the new user
    if(userFromDB){
      response.status(400).send("User name already exists");
    }else{
      // password is hashed
      const hashedPassword = await generateHashedPassword(password); 
      console.log(hashedPassword)
      const result = await client.db("node")
                                 .collection("users")
                                 .insertOne({ "userName" : userName,
                                              "email" : email,
                                              "password" : hashedPassword
                                           })
      response.send("Sign up successful")
    }   
})

// log in 
app.post("/login", async function( request, response) {
  const {userName, password} = request.body;

  // check whether user is present in the database
  const userFromDB = await client.db("node").collection("users").findOne({ "userName" : userName})

  // if username is invalid return error message else check for the password
  if(!userFromDB){
    response.send({message : "Invalid credentials"})
  }else{
    const storedPassword = userFromDB.password;
    const isPasswordMatch = await bcrypt.compare(password, storedPassword);
    if(isPasswordMatch){
      response.send({message: "Login Successfull"})
    }else{
      response.status(400).send({message: "Invalid credentials"})
    } 
  } 
})

// forgot password
app.post("/forgotPassword", async function(request, response){
  const {email} = request.body;
  // check whether the email is present in the database
  const emailFromDB = await client.db("node").collection("users").findOne({"email": email});

  // if email is not present send error message
  if(!emailFromDB){
    response.status(400).send({message: "Please enter a valid email"});
  }else{
    //generate a random string if email is valid
    const randomStr = randomstring.generate();

    // mail sent using nodemailer

    // create transporter
    let transporter = nodemailer.createTransport({
       service: "gmail",
       auth : {
          user : process.env.USER_NAME,
          pass : "xxjonkhamtoefulk"
       }
    })
    // mail details
    let mailDetails = {
            from: 'no-reply@noreplay.com',
            to: email,
            subject: 'Reset Password',
            text : "HI this is a testing mail"
            // html: `<h4>Hello User,</h4><br><p> You can reset the password by clicking the link below.</p><br><u><a href=${linkForUser}>${linkForUser}</a></u>`
        }

    // send mail
    transporter.sendMail(mailDetails, (err, data)=>{
      if (err) {
        console.log(err)
      }else{
        console.log("Mail sent successfully")
      }
    })

    // set the expiry time limit for the link to work
    const expiresin = new Date();
    // expiry within 1 hour
    expiresin.setHours(expiresin.getHours() + 1);
    //storing the random string
    await client.db("node").collection("users")
                           .findOneAndUpdate(
                                             {email: email},
                                             { 
                                              $set : 
                                                {
                                                  resetPaswordToken: randomStr,
                                                  resetPasswordExpiresOn: expiresin
                                                }
                                             }
                                             )
    response.send("Password reset link is sent to your mail")
  }
})

// verify whether the random string matches or not
app.post("/verifyToken", async function(request, response) {
  const {id, token} = request.body;
  //get the user from the database
  const userFromDB = await client.db("node").collection("users").findOne({_id:ObjectId(id)})
  // the current time when the link is clicked
  const currentTime = new Date();
  currentTime.setHours(currentTime.getHours())
  
  try{
    if(currentTime <= userFromDB.resetPasswordExpiresOn){
      if(token === userFromDB.resetPaswordToken){
        response.send({msg: "Changing Password is approved"})
      }else{
        response.status(400).send({msg:"Token is not valid"})
      }
    }else{
      response.status(400).send({msg:"Link expired"})
    }
  }catch(err){
    response.status(400).send({msg:"Something went wrong"})
  }

})

app.post("/changePassword", async function(request, response){
  const {id, password} = request.body;

  try{
  const hashedPassword = await generateHashedPassword(password)
  const userFromDB = await client.db("node")
                                 .collection("users")
                                 .findOneAndUpdate(
                                  { _id: ObjectId(id) },
                                  { $set: {password: hashedPassword } } 
                                  )

    response.send("Password has been updated successfully")                              
  }catch(err){
    response.status(400).send({msg: "Error"})
  }
})



app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));
