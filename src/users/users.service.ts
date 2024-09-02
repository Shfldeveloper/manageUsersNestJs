import { BadRequestException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { Request } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class UsersService {
    constructor(private prisma: PrismaService) { }

    async getSingleUser(id: string , req : Request) {
        const foudedUser = await this.prisma.user.findUnique({ where: { id: id }, select: { id: true, email: true } })

        if(!foudedUser){
            throw new NotFoundException('there is no such a user with this id')
        }

        const decodedUser = req.user as {id:string , email : string}

        if(foudedUser.id !== decodedUser.id){
            throw new ForbiddenException("you can't have access to this route")
        }

        return foudedUser

    }

    async getAllUsers() {
        return await this.prisma.user.findMany({ select: { id: true, email: true } })
    }
}
