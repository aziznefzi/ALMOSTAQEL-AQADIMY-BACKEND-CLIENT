import jwt from "jsonwebtoken"
const filedAuth = async (req, res, next) => {
    try{
      const authHeader = req.headers.authorization;
      if(!authHeader) return res.status(403).json({message: "Authorization header missing"})
      const token = authHeader.split(" ")[1];
      if(!token) res.status(403).json({message: "Token is missing"})
      const accessToken = jwt.verify(token, process.env.ACCESS_TOKEN)
      if(accessToken.type !== "email-verification") return res.status(403).json({message: "Invalid verification token"})
      req.user = accessToken;
      next()
    }catch(err){
        console.log("invalid or expired token: ", err)
        return res.status(405).json(`invalid or expired token: ${err}`)
    }
}

export default filedAuth;