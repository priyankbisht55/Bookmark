import { Injectable } from "@nestjs/common";
import { AuthDto } from "./dto";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from 'argon2';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}

    async signup(dto: AuthDto) {

        // generate the password hash
        const hash = await argon.hash(String(dto.password));
        // save the new user in the db 
        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash,
            },
        });
        // return the saved user
        return user;
    }

    signin() {
        return {msg: 'I am signed in'};
    }
}