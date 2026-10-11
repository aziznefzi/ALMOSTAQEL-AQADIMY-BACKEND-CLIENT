import jwt from "jsonwebtoken"
const filedAuth = async (req, res, next) => {
    try{
      let token = req.cookies?.verificationToken || req.cookies?.accessToken;
      if (!token && req.headers.authorization) {
        const authHeader = req.headers.authorization;
        token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
      }

      if (!token) {
        return res.status(403).json({ message: "Verification token missing" });
      }

      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN)
      if(decoded.type !== "email-verification") return res.status(403).json({message: "Invalid verification token"})
      
      // Device Binding Protection: Verify that the request is made from the authorized device
      const incomingDeviceId = req.headers['x-device-id'] || req.headers['device-id'] || req.body?.deviceId || req.query?.deviceId;
      if (decoded.deviceId && incomingDeviceId && decoded.deviceId !== incomingDeviceId) {
        return res.status(403).json({ message: "Security alert: Token used from unauthorized device" });
      }

      req.user = decoded;
      next()
    }catch(err){
        console.log("invalid or expired token: ", err)
        return res.status(405).json({ message: `invalid or expired token: ${err.message || err}` })
    }
}

export default filedAuth;