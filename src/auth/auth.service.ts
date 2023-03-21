import { Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2";
import { ForbiddenException } from "@nestjs/common/exceptions";
import { JwtService } from "@nestjs/jwt/dist";
import { ConfigService } from "@nestjs/config/dist/config.service";

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}

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
    return this.signToken(user.id, user.email);
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

      // return the saved user
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error.code == "P2002") {
        throw new ForbiddenException("Credentials taken");
      }
      throw error;
    }
  }

  async signToken(userId: number, email: string): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get("JWT_SECRET");

    const token = await this.jwt.signAsync(payload, {
      expiresIn: "15min",
      secret: this.config.get("JWT_SECRET"),
    });

    return {
      access_token: token,
    };
  }
}
