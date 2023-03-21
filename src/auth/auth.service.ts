import { Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { ForbiddenException } from "@nestjs/common/exceptions";

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signin(dto: AuthDto) {
    // find user by id
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    //if user does not exist throw exception
    if (!user) throw new ForbiddenException("Credentials incorrect");

    //compere password
    const pwMatches = await argon.verify(user.hash, dto.password);

    //if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException("Credentials incorrect");

    // send back the user
    delete user.hash;
    return user;
  }

  async signup(dto: AuthDto) {
    // generate the password
    const hash = await argon.hash(dto.password);

    try {
      //Save the user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      // return the saved user
      return user;
    } catch (error) {
      if (error.code == "P2002") {
        throw new ForbiddenException("Credentials taken");
      }
      throw error;
    }
  }
}
