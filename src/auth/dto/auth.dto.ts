import { IsEmail, IsNotEmpty, IsString, Length } from "class-validator";


export class AuthDto {
    @IsNotEmpty()
    @IsString()
    @IsEmail()
    public email: string;

    @IsString()
    @IsNotEmpty()
    @Length(5,20,{message : 'the password length should between 5 and 20!'})
    public password: string;
}