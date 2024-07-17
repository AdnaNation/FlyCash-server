const { MongoClient, ServerApiVersion } = require('mongodb');
const express = require('express')
const app = express()
require('dotenv').config()
const jwt = require('jsonwebtoken');
const cors = require('cors')
const bcrypt = require('bcryptjs');
const port = process.env.PORT || 5000;

// middleware
const corsOptions = {
    origin: ['http://localhost:5173'],
    credentials: true,
    optionSuccessStatus: 200,
  }
  app.use(cors(corsOptions))
  app.use(express.json());


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.vksh2ow.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;


// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    const userCollection = client.db("FlyCashDB").collection("users");

      // jwt related api
      app.post('/jwt', async (req, res) => {
        const user = req.body;
        console.log(user)
       const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '24h' });
       res.send({ token });
     })

     // middlewares 
     const verifyToken = (req, res, next) => {
      console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next();
      })
    }

    const verifyAdmin = async (req, res, next) => {
      const emailOrPhone = req.decoded.emailOrPhone;
      const query = { emailOrPhone: emailOrPhone };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === 'admin';
      if (!isAdmin) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    }
    const verifyAgent = async (req, res, next) => {
      const emailOrPhone = req.decoded.emailOrPhone;
      const query = { emailOrPhone: emailOrPhone };
      const user = await userCollection.findOne(query);
      const isAgent = user?.role === 'agent';
      if (!isAgent) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    }

    // users related api
    app.get('/users/admin/:emailOrPhone', verifyToken, async (req, res)=>{
      const emailOrPhone = req.params.emailOrPhone;
      if (emailOrPhone !== req.decoded.emailOrPhone){
        return res.status(403).send({ message: 'forbidden access' })
      }
      const query = {emailOrPhone:emailOrPhone};
      const user = await userCollection.findOne(query);
      let admin = false;
      if(user){
        admin = user?.role === 'admin';
      }
      res.send({admin})
    })
    app.post('/users', async (req, res) => {
        const user = req.body;
        const query = { emailOrPhone: user.emailOrPhone }
        const existingUser = await userCollection.findOne(query);
        if (existingUser) {
          return res.send({ message: 'User already exists', insertedId: null })
        }
        const result = await userCollection.insertOne(user);
        res.send(result);
      });
      app.post('/user', async( req, res)=>{
        const user = req.body;
        console.log(user);
        const query = {emailOrPhone: user.emailOrPhone}
        const userFromDb = await userCollection.findOne(query)
        console.log(userFromDb)
        if (!userFromDb) {
            return res.status(400).json({ message: "User with this email/number doesn't exist" });
          }

          const isPinValid = await bcrypt.compare(req.body.hashedPin, userFromDb.pin);
          console.log(isPinValid)
  if (!isPinValid) {
    return res.status(400).send({ message: "Incorrect Pin" });
  }

  res.status(200).send({ message: 'Login successful' });
      })

      app.get('/users', async (req, res)=>{
        const users = await userCollection.find().toArray();
        res.send(users)
      })
       app.get('/user/:emailOrPhone',verifyToken, async (req, res)=>{
        const emailOrPhone = req.params.emailOrPhone
        const query = {emailOrPhone: emailOrPhone}
        const user = await userCollection.findOne(query)
        res.send(user)
       })



    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('FlyCash server is running')
})

app.listen(port, () => {
    console.log(`FlyCash server on port ${port}`);
})