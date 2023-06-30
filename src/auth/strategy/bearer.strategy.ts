import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { StaticBearerStrategy } from './static-bearer.strategy';

@Injectable()
export class WrappingStaticBearerStrategy extends PassportStrategy(StaticBearerStrategy, 'static-bearer') {
  constructor(private authService: AuthService) {
    super({ },true, async (apiKey: string, done: (arg0: UnauthorizedException, arg1: boolean) => void) => {
      if (this.authService.validateApiKey(apiKey)) {
        done(null, true);
      }
      done(new UnauthorizedException(), null);
    });
  }
}
