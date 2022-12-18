<?php

declare(strict_types=1);

namespace Fschmtt\Keycloak\Test\Unit\Resource;

use Fschmtt\Keycloak\Collection\UserCollection;
use Fschmtt\Keycloak\Http\Command;
use Fschmtt\Keycloak\Http\CommandExecutor;
use Fschmtt\Keycloak\Http\Method;
use Fschmtt\Keycloak\Http\Query;
use Fschmtt\Keycloak\Http\QueryExecutor;
use Fschmtt\Keycloak\Representation\User;
use Fschmtt\Keycloak\Resource\Users;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Fschmtt\Keycloak\Resource\Users
 */
class UsersTest extends TestCase
{
    public function testGetAllUsers(): void
    {
        $query = new Query(
            '/admin/realms/{realm}/users',
            UserCollection::class,
            [
                'realm' => 'test-realm',
            ],
        );

        $clientCollection = new UserCollection([
            new User(id: 'test-user-1'),
            new User(id: 'test-user-2'),
        ]);

        $queryExecutor = $this->createMock(QueryExecutor::class);
        $queryExecutor->expects(static::once())
            ->method('executeQuery')
            ->with($query)
            ->willReturn($clientCollection);

        $clients = new Users(
            $this->createMock(CommandExecutor::class),
            $queryExecutor,
        );

        static::assertSame(
            $clientCollection,
            $clients->all('test-realm')
        );
    }

    public function testGetUser(): void
    {
        $query = new Query(
            '/admin/realms/{realm}/users/{userId}',
            User::class,
            [
                'realm' => 'test-realm',
                'userId' => 'test-user',
            ],
        );

        $client = new User(id: 'test-user-1');

        $queryExecutor = $this->createMock(QueryExecutor::class);
        $queryExecutor->expects(static::once())
            ->method('executeQuery')
            ->with($query)
            ->willReturn($client);

        $clients = new Users(
            $this->createMock(CommandExecutor::class),
            $queryExecutor,
        );

        static::assertSame(
            $client,
            $clients->get('test-realm', 'test-user')
        );
    }

    public function testCreateUser(): void
    {
        $createdUser = new User(id: 'uuid', username: 'imported-user');

        $command = new Command(
            '/admin/realms/{realm}/users',
            Method::POST,
            [
                'realm' => 'test-realm',
            ],
            $createdUser,
        );

        $commandExecutor = $this->createMock(CommandExecutor::class);
        $commandExecutor->expects(static::once())
            ->method('executeCommand')
            ->with($command);

        $users = new Users(
            $commandExecutor,
            $this->createMock(QueryExecutor::class),
        );

        $users->create('test-realm', $createdUser);
    }

    public function testDeleteUser(): void
    {
        $deletedUser = new User(id: 'deleted-user');

        $command = new Command(
            '/admin/realms/{realm}/users/{userId}',
            Method::DELETE,
            [
                'realm' => 'test-realm',
                'userId' => $deletedUser->getId(),
            ],
        );

        $commandExecutor = $this->createMock(CommandExecutor::class);
        $commandExecutor->expects(static::once())
            ->method('executeCommand')
            ->with($command);

        $users = new Users(
            $commandExecutor,
            $this->createMock(QueryExecutor::class),
        );

        $users->delete('test-realm', $deletedUser->getId());
    }

    public function testUpdateUser(): void
    {
        $updatedUser = new User(id: 'test-user', username: 'new-username');

        $command = new Command(
            '/admin/realms/{realm}/users/{userId}',
            Method::PUT,
            [
                'realm' => 'test-realm',
                'userId' => 'test-user',
            ],
            $updatedUser,
        );

        $commandExecutor = $this->createMock(CommandExecutor::class);
        $commandExecutor->expects(static::once())
            ->method('executeCommand')
            ->with($command);

        $users = new Users(
            $commandExecutor,
            $this->createMock(QueryExecutor::class),
        );

        $users->update('test-realm', 'test-user', $updatedUser);
    }

    public function testSearchUser(): void
    {
        $criteria = [
            'username' => 'test-user',
            'exact' => true,
        ];

        $query = new Query(
            '/admin/realms/{realm}/users?{criteria}',
            UserCollection::class,
            [
                'realm' => 'test-realm',
                'criteria' => http_build_query($criteria),
            ],
        );

        $queryExecutor = $this->createMock(QueryExecutor::class);
        $queryExecutor->expects(static::once())
            ->method('executeQuery')
            ->with($query)
            ->willReturn(new UserCollection());

        $users = new Users(
            $this->createMock(CommandExecutor::class),
            $queryExecutor,
        );

        $users->search('test-realm', $criteria);
    }
}
