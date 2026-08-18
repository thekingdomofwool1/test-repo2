<?php
/**
 * REPO 2: PHP / Yii Framework Security Test Suite
 * Targets: Yii-specific XSS, dynamic method invocation, and unparameterized SQL queries.
 */

namespace app\controllers;

use Yii;
use yii\web\Controller;
use yii\web\Response;

class SiteController extends Controller
{
    // =========================================================================
    // RULE 1: Potential Cross-Site Scripting (XSS) Vulnerability in Yii PHP Framework
    // Pattern: Echoing Yii::$app->request inputs directly without Html::encode()
    // =========================================================================
    public function actionSearch()
    {
        // Taint Source: Raw GET parameter from Yii request component
        $searchTerm = Yii::$app->request->get('q', '');
        $category = Yii::$app->request->get('category', '');

        // Taint Sink 1: Direct unencoded echo of request input
        echo "<h1>Search results for: " . $searchTerm . "</h1>";

        // Taint Sink 2: Returning unencoded HTML via renderContent
        $htmlOutput = "<div class='alert'>Selected category: " . $category . "</div>";
        return $this->renderContent($htmlOutput);
    }

    public function actionProfileView()
    {
        // Taint Source: Unfiltered request body parameter
        $userBio = Yii::$app->request->post('bio');

        // Taint Sink 3: Passing raw unescaped input to view without Html::encode
        return $this->render('profile', [
            'bio' => $userBio, // Rendered in view as <?= $bio ?> without encoding
        ]);
    }


    // =========================================================================
    // RULE 2: Unsafe Dynamic Method Invocation in PHP
    // Pattern: Variable function/method calls based on unvalidated input
    // =========================================================================
    public function actionDispatch()
    {
        // Taint Source: Method name supplied by user
        $actionMethod = Yii::$app->request->get('method_name');
        $param = Yii::$app->request->get('param');

        $serviceHandler = new \app\components\PluginManager();

        // Taint Sink 1: Direct variable method call
        $result1 = $serviceHandler->$actionMethod($param);

        // Taint Sink 2: call_user_func with user-controlled callable
        $callbackName = Yii::$app->request->post('callback');
        $result2 = call_user_func($callbackName, $param);

        return $this->asJson([
            'result1' => $result1,
            'result2' => $result2,
        ]);
    }


    // =========================================================================
    // RULE 3: Unauthenticated SQL injection via unparameterized query in getUserHandler
    // Pattern: Action/handler named getUserHandler with raw SQL string concatenation
    // =========================================================================
    public function actionGetUserHandler()
    {
        // Taint Source: User ID from GET request
        $userId = Yii::$app->request->get('id');

        // Taint Sink: Raw SQL string concatenation without parameter binding (:id)
        $rawSql = "SELECT * FROM user WHERE id = " . $userId . " AND is_active = 1";
        
        $db = Yii::$app->db;
        $userData = $db->createCommand($rawSql)->queryAll();

        return $this->asJson(['user' => $userData]);
    }


    // =========================================================================
    // Additional PHP Sinks: eval() & Insecure Deserialization
    // =========================================================================
    public function actionExecuteCustomLogic()
    {
        $code = Yii::$app->request->post('custom_code');
        // Unsafe evaluation of PHP code
        eval($code);

        $serializedData = Yii::$app->request->post('state');
        // Insecure PHP deserialization
        $object = unserialize($serializedData);

        return $this->asJson(['status' => 'executed']);
    }
}
