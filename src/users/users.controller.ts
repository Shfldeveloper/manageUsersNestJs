import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/jwt.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  @UseGuards(JwtAuthGuard)
  @Get(':id')
  getSingleUser(@Param() params : {id : string} , @Req() req){
    return this.usersService.getSingleUser(params.id , req)
  }

  @Get()
  getAllUsers(){

    return this.usersService.getAllUsers()

  }
}
