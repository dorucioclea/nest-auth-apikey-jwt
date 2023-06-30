import * as _ from 'lodash';
import { Request } from 'express';
import { Strategy as PassportStrategy } from 'passport-strategy';
import { PassportStrategy as WrappingStrategy} from '@nestjs/passport';
import { BadRequestError } from '../../errors/bad-request.error';
import { AuthService } from '../auth.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';

class InnerStaticBearerStrategy extends PassportStrategy {

    staticAuthorizationHeader: { header: string } = { header: 'Authorization' };
    name: string;
    verify: (apiKey: string, verified: (err: Error | null, user?: Object, info?: Object) => void, req?: Request) => void;
    passReqToCallback: boolean;

    constructor(verify: (apiKey: string, verified: (err: Error | null, user?: Object, info?: Object) => void, req?: Request) => void) {
        super();
        this.staticAuthorizationHeader.header = this.staticAuthorizationHeader.header.toLowerCase();

        this.name = 'static-bearer';
        this.verify = verify;
    }

    authenticate(req: Request, options?: Object): void {
        let apiKey: string = _.get(req.headers, this.staticAuthorizationHeader.header) as string;
        if (!apiKey) {
            return this.fail(new BadRequestError('Missing static bearer key'), null);
        }

        let verified = (err: Error | null, user?: Object, info?: Object) => {
            if (err) {
                return this.error(err);
            }
            if (!user) {
                return this.fail(info, null);
            }
            this.success(user, info);
        };

        this.verify(apiKey, verified, ...[]);
    }
}


@Injectable()
export class StaticBearerStrategy extends WrappingStrategy(InnerStaticBearerStrategy, 'static-bearer') {
  constructor(private authService: AuthService) {
    super(async (apiKey: string, done: (arg0: UnauthorizedException, arg1: boolean) => void) => {
      if (this.authService.validateApiKey(apiKey)) {
        done(null, true);
      }
      done(new UnauthorizedException(), null);
    });
  }
}