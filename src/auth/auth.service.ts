import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import {Request , Response} from 'express'

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService) { }

    async signup(authDto: AuthDto) {

        const { email, password } = authDto

        const foundUser = await this.prisma.user.findUnique({ where: { email } })
        if (foundUser) {
            throw new BadRequestException('this email is taken')
        }

        const hashedPassword = await this.hashPassword(password)

        const newUser = await this.prisma.user.create({
            data: {
                email,
                hashedPassword
            }
        })

        let resUser = newUser
        delete resUser.hashedPassword

        return resUser
        // return {message : "new user added succesfully."}
    }
    async signin(authDto: AuthDto, req: Request, res: Response) {
        const { email, password } = authDto
        const foundedUser = await this.prisma.user.findUnique({ where: { email } })
        if (!foundedUser) {
            throw new BadRequestException('there is no such a user with this email./ Wrong credential.')
        }

        const isMatch = await this.comparePasswords({ password, hashedpas: foundedUser.hashedPassword })

        if (!isMatch) {
            throw new BadRequestException('wrong password try again:(')
        }

        const jwtToken = await this.signToken({ id: foundedUser.id, email: foundedUser.email })

        if(!jwtToken){
            throw new ForbiddenException()
        }

        
        res.cookie('token',jwtToken)

        return res.send({message : 'logged In Succesfully:)'})


    }
    async signout(req: Request, res: Response) {

        res.clearCookie('token')
        return res.send({message : 'you have logged out successfully'})

    }

    async hashPassword(password: string) {
        const saltOrRound: number = 10
        const hashedPassword: string = await bcrypt.hash(password, saltOrRound)
        return hashedPassword
    }

    async comparePasswords(args: { password: string, hashedpas: string }) {
        return await bcrypt.compare(args.password, args.hashedpas)
    }

    async signToken(args: { id: string, email: string }) {
        const payload = args
        return this.jwt.signAsync(payload, { secret: jwtSecret })
    }


}
