import bcrypt from "bcrypt";
import express from "express";
import { MongoClient } from "mongodb";
import randomstring from "randomstring";
import nodemailer, { createTransport } from "nodemailer";
const app = express();

const PORT = 4000;

// connection to mongodb
const MONGO_URL= "mongodb://127.0.0.1"

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

// function to generate hashed password
async function generateHashedPassword(password){
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password,salt);
  return hashedPassword;
}

// sign up 
app.post("/signup", async function(request, response){
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
//const randomString = randomstring.generate()
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
          user : "tharunmano1170@gmail.com",
          pass : "xxjonkhamtoefulk"
       }
    })
    // mail details
    let mailDetails = {
            from: 'tharunmano1170@gmail.com',
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



app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));
