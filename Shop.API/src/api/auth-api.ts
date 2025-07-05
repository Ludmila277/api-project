import { Request, Response, Router } from "express";
import { IAuthRequisites } from "@Shared/types";
import { connection } from "../../index";
import { IUserRequisitesEntity } from "../../types";
import bcrypt from "bcrypt";

export const authRouter = Router();

authRouter.post(
  "/",
  async (req: Request<{}, {}, IAuthRequisites>, res: Response) => {
    try {
      const { username, password } = req.body;

      // Проверка наличия обязательных полей
      if (!username || !password) {
        return res.status(400).json({ message: "Недостаточно данных" });
      }

      // Получаем пользователя по имени
      const [user] = await connection.query<IUserRequisitesEntity[]>(
        "SELECT * FROM users WHERE username = ?",
        [username]
      );

      // Проверяем существование пользователя
      if (!user || user.length === 0) {
        return res.status(404).json({ message: "Пользователь не найден" });
      }

      // Сравниваем хеши паролей
      const isPasswordValid = await bcrypt.compare(
        password,
        user[0].password_hash
      );

      if (!isPasswordValid) {
        return res.status(401).json({ message: "Неверный пароль" });
      }

      // Здесь можно добавить логику авторизации (токены, сессии и т.д.)
      res.status(200).json({ message: "Успешная авторизация" });
    } catch (error) {
      console.error("Ошибка при авторизации:", error);
      res.status(500).json({ message: "Внутренняя ошибка сервера" });
    }
  }
);
