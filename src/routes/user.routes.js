import { Router } from "express";
import {
	loginUser,
	logoutUser,
	registerUser,
} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

/**
 * path: api/v1/users/register
 */
router.route("/register").post(
	upload.fields([
		{
			name: "avatar",
			maxCount: 1,
		},
		{
			name: "coverImage",
			maxCount: 1,
		},
	]),
	registerUser
);

/**
 * path: api/v1/users/login
 */
router.route("/login").post(loginUser);

/********************/
/** secured routes */
/********************/

/**
 * path: api/v1/users/logout
 */
router.route("/logout").post(verifyJWT, logoutUser);

export default router;
