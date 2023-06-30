import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { StaticBearerStrategy } from './strategy/static-bearer.strategy';

@Module({
  imports: [
    PassportModule
  ],
  providers: [AuthService, StaticBearerStrategy],
  exports: [AuthService],
})
export class AuthModule {}
