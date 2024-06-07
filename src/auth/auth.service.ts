import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';

import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-Payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ){}

//INIICIO METODO PARA CREAR USUARIO
  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      // 1 - Encriptar la contraseña
      const {password, ...userData} = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });
      // 2 - Guardar el usuario 
      await newUser.save();

      const {password:_, ...user} = newUser.toJSON();
      return user;
      
    } catch (error) {
      if(error.code ===11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('Something terribe happend!!')
    }
  } //FIN METODO PARA CREAR USUARIO

  //INICIO MÉTODO LOGIN
  async login(loginDto : LoginDto):Promise<LoginResponse>{

    const {email, password} = loginDto;
    const user = await this.userModel.findOne({email: email});
    
    if(!user){
      throw new UnauthorizedException('Not valid credential - email invalid');
    }

    if(!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credential - password incorrecto');
    }
    const {password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token:  this.getJwtToken({id: user.id})
    }
  }  //FIN MÉTODO LOGIN


  //INICIO METODO PARA REGISTRAR UN USUARIO 
  async register(registerDTO: RegisterDto):Promise<LoginResponse>{

    const user = await this.create(registerDTO);

    return{
      user: user,
      token: this.getJwtToken({id : user._id})
    }
  }
  //FIN METODO PARA REGISTRAR UN USUARIO 



  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  // 3 - Generar JWT 
   getJwtToken(payload : JwtPayload){
    const token =   this.jwtService.sign(payload);
    return token;
  }
}
