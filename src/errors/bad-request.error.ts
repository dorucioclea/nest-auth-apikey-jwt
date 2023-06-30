export class BadRequestError implements Error {
    name: string;
    message: string;

    constructor(message: string) {
        this.name = 'BadRequestError';
        this.message = message;
    }
}