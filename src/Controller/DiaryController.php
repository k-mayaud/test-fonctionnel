<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\FoodType;
use App\Services\Diary;
use App\Entity\FoodRecord;
use Datetime;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Translation\TranslatableMessage;
use Symfony\Contracts\Translation\TranslatableInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

#[Route(path: '/diary')]
class DiaryController extends AbstractController
{
    #[Route(path: '/homepage', name: 'homepage')]
    #[IsGranted('ROLE_USER')]
    public function indexAction(): Response
    {
        return $this->render(
            'diary/index.html.twig',
            [
                'github_client_id' => $this->getParameter('github.id'),
            ]
        );
    }

    #[Route(path: '/list', name: 'diary')]
    #[IsGranted('ROLE_USER')]
    public function listAction(EntityManagerInterface $entityManager): Response
    {
        return $this->render(
            'diary/list.html.twig',
            [
                'records' => $entityManager->getRepository(FoodRecord::class)->findBy(
                    [
                        'userId' => $this->getUser()->getId(),
                        'recordedAt' => new Datetime(),
                    ]
                )
            ]
        );
    }

    #[Route(path: '/add-new-record', name: 'add-new-record')]
    #[IsGranted('ROLE_USER')]
    public function addRecordAction(Request $request, EntityManagerInterface $entityManager, TranslatorInterface $translator): RedirectResponse|Response
    {
        $foodRecord = new FoodRecord($this->getUser());
        $form = $this->createForm(FoodType::class, $foodRecord);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $entityManager->persist($foodRecord);
            $entityManager->flush();

            $this->addFlash('success', $translator->trans('A new entry in your diary has been successfully added').'.');

            return $this->redirectToRoute('add-new-record');
        }

        return $this->render('diary/addRecord.html.twig', ['form' => $form->createView()]);
    }

    #[Route(path: '/delete-record', name: 'delete-record')]
    #[IsGranted('ROLE_USER')]
    public function deleteRecordAction(Request $request, CsrfTokenManagerInterface $tokenManager, EntityManagerInterface $entityManager, TranslatorInterface $translator): RedirectResponse
    {
        if (!$record = $entityManager->getRepository(FoodRecord::class)->findOneById($request->request->get('record_id'))) {
            $this->addFlash('danger', $translator->trans('Log entry does not exist').'.');

            return $this->redirectToRoute('diary');
        }

        $csrf_token = new CsrfToken('delete_record', $request->request->get('_csrf_token'));

        if ($tokenManager->isTokenValid($csrf_token)) {
            $entityManager->remove($record);
            $entityManager->flush();

            $this->addFlash('success', $translator->trans('The entry has been successfully deleted from the log').'.');
        } else {
            $this->addFlash('error', $translator->trans('An error has occurred').'.');
        }

        return $this->redirectToRoute('diary');
    }

    #[Route(path: '/calories-status', name: 'calories-status')]
    public function caloriesStatusAction(Diary $diary): Response
    {
        return $this->render(
            'diary/caloriesStatus.html.twig',[
                'remainingCalories' => $diary->getDailyRemainingCalories($this->getUser(), new Datetime()),
                'maxCalories' => User::MAX_ADVICED_DAILY_CALORIES
            ]
        );
    }
}
