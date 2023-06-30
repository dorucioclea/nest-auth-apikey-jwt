import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { WrappingStaticBearerStrategy } from './strategy/bearer.strategy';

@Module({
  imports: [
    PassportModule
  ],
  providers: [AuthService, WrappingStaticBearerStrategy],
  exports: [AuthService],
})
export class AuthModule {}
