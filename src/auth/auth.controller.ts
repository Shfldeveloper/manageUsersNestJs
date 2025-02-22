import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }
  @Post('signup')
  signup(@Body() authDto: AuthDto) {
    return this.authService.signup(authDto)
  }

  @Post("signin")
  signin(@Body() authDto: AuthDto, @Req() req, @Res() res) {
    return this.authService.signin(authDto, req, res)
  }

  @Get("signout")
  signout(@Req() req, @Res() res) {
    return this.authService.signout(req, res)
  }


}
