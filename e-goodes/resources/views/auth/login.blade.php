<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <link rel="stylesheet" href="{{ asset('css/login.css') }}">
    <title>e-goodes , easy digital shopping</title>
</head>

<body>
    
    <div class="container" id="container">
        <!-- Sign Up Form -->
        <div class="form-container sign-up">
            <form action="{{ route('signup') }}" method="POST">
                @csrf 
                <h1>Create Account</h1>
                <div class="social-icons">
                    <a  class="icon"><i class="fab fa-google-plus-g"></i></a>
                    <a  class="icon"><i class="fab fa-facebook-f"></i></a>
                    <a  class="icon"><i class="fab fa-github"></i></a>
                    <a  class="icon"><i class="fab fa-linkedin-in"></i></a>
                </div>
                <span>or use your email for registration</span>
                <input type="text" name="name" placeholder="Name" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <div class="role-selection">
                    <label for="role">Select Role:</label>
                    <select name="role" id="role">
                        <option value="user">User</option>
                        <option value="organisateur">Organisateur</option>
                    </select>
                </div>
                <button type="submit" class="signup-btn">Sign Up</button> 
            </form>
        </div>
        <!-- Login Form -->
        <div class="form-container sign-in">
            <form action="" method="POST">
                @csrf 
                <h1>Sign In</h1>
                <div class="social-icons">
                    <a class="icon"><i class="fab fa-google-plus-g"></i></a>
                    <a class="icon"><i class="fab fa-facebook-f"></i></a>
                    <a class="icon"><i class="fab fa-github"></i></a>
                    <a class="icon"><i class="fab fa-linkedin-in"></i></a>
                </div>
                <span>or use your email password</span>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <a href="">Forgot Your Password?</a>
                <button type="submit">Sign In</button>
            </form>
        </div>

        <div class="toggle-container">
            <div class="toggle">
                <div class="toggle-panel toggle-left">
                    <h1>Welcome Back!</h1>
                    <p>Enter your personal details to use all of site features</p>
                    <button class="hidden" id="login">Sign In</button>
                </div>
                <div class="toggle-panel toggle-right">
                    <h1>Hello, Friend!</h1>
                    <p>Register with your personal details to use all of site features</p>
                    <button class="hidden" id="register">Sign Up</button>
                </div>
            </div>
        </div>
    </div>

    <script src="{{ asset('js/login.js') }}"></script>
</body>

</html>
