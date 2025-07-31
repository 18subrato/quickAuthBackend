import User from '../models/userModel.js'

export const getUserData = async(req,res)=>{
    try {
        const userId  = req.user;

        const user = await User.findById(userId);
        if(!user){
            return res.json({success: false, message: 'User not Found'});
        }

        return res.json({success: true, 
            userData:{
                name: user.name,
                isAccountVerified: user.isAccountVerified,  
            }})


    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}